import os
import uuid
from datetime import date, datetime, timedelta
from functools import wraps

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"


DEFAULT_FOLDERS = ["Documents", "Pictures", "Videos"]
ROOT_FOLDER_NAME = "__root__"


def file_disk_path(upload_root: str, user_id: int, folder_id: int, stored_filename: str) -> str:
    return os.path.join(upload_root, str(user_id), str(folder_id), stored_filename)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    is_bookmarked = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    __table_args__ = (UniqueConstraint("user_id", "name", name="uq_folder_user_name"),)


class VaultFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    folder_id = db.Column(db.Integer, db.ForeignKey("folder.id"), nullable=False, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    content_type = db.Column(db.String(255), nullable=True)
    size_bytes = db.Column(db.Integer, nullable=False, default=0)
    uploaded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class ShareLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    token = db.Column(db.String(64), nullable=False, unique=True, index=True)
    item_type = db.Column(db.String(16), nullable=False)  # 'file' | 'folder'
    item_id = db.Column(db.Integer, nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def admin_required(view_fn):
    @wraps(view_fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not getattr(current_user, "is_admin", False):
            abort(403)
        return view_fn(*args, **kwargs)

    return wrapper


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-change-me"),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "DATABASE_URL", f"sqlite:///{os.path.join(app.instance_path, 'vault.db')}"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_CONTENT_LENGTH", str(200 * 1024 * 1024))),
        UPLOAD_ROOT=os.environ.get("UPLOAD_ROOT", os.path.join(app.instance_path, "uploads")),
    )

    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        db.create_all()
        ensure_schema()
        ensure_default_admin()
        ensure_default_folders_for_all_users()

    @app.context_processor
    def inject_sidebar_folders():
        if current_user.is_authenticated and not getattr(current_user, "is_admin", False):
            ensure_default_folders_for_user(current_user.id)
            all_folders = Folder.query.filter_by(user_id=current_user.id).order_by(Folder.name.asc()).all()
            pinned_folders = (
                Folder.query.filter_by(user_id=current_user.id, is_bookmarked=True)
                .filter(Folder.name != ROOT_FOLDER_NAME)
                .order_by(Folder.name.asc())
                .all()
            )
            return {"sidebar_folders": pinned_folders, "all_folders": all_folders}
        return {"sidebar_folders": [], "all_folders": []}

    @app.get("/")
    def index():
        if current_user.is_authenticated:
            if current_user.is_admin:
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.get("/signup")
    def signup():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return render_template("register.html")

    @app.post("/signup")
    def signup_post():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""

        if not username:
            flash("Username is required.", "error")
            return redirect(url_for("signup"))
        if len(username) < 3:
            flash("Username must be at least 3 characters.", "error")
            return redirect(url_for("signup"))
        if not password:
            flash("Password is required.", "error")
            return redirect(url_for("signup"))
        if password != password2:
            flash("Passwords do not match.", "error")
            return redirect(url_for("signup"))

        existing = User.query.filter_by(username=username).first()
        if existing:
            flash("That username is already taken.", "error")
            return redirect(url_for("signup"))

        user = User(username=username, password_hash=generate_password_hash(password), is_admin=False)
        db.session.add(user)
        db.session.commit()

        ensure_default_folders_for_user(user.id)

        login_user(user)
        return redirect(url_for("dashboard"))

    @app.get("/login")
    def login():
        if current_user.is_authenticated:
            if current_user.is_admin:
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        if current_user.is_authenticated:
            if current_user.is_admin:
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        login_user(user)
        if user.is_admin:
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        if current_user.is_admin:
            return redirect(url_for("admin_dashboard"))
        ensure_default_folders_for_user(current_user.id)
        root_folder = get_or_create_root_folder(current_user.id)
        folders = (
            Folder.query.filter_by(user_id=current_user.id)
            .filter(Folder.name != ROOT_FOLDER_NAME)
            .order_by(Folder.created_at.desc())
            .all()
        )
        root_files = VaultFile.query.filter_by(user_id=current_user.id, folder_id=root_folder.id).order_by(
            VaultFile.uploaded_at.desc()
        )
        breadcrumbs = [("Vault", url_for("dashboard"))]
        return render_template(
            "explorer.html",
            breadcrumbs=breadcrumbs,
            selected_folder=None,
            selected_folder_id=None,
            folders=folders,
            files=root_files,
            root_folder_id=root_folder.id,
        )

    def build_public_share_url(token: str) -> str:
        return url_for("shared_access", token=token, _external=True)

    def parse_share_minutes(raw: str | None) -> int:
        if raw is None:
            return 30
        try:
            minutes = int(str(raw).strip())
        except (TypeError, ValueError):
            return 30
        if minutes < 1:
            minutes = 1
        if minutes > 60 * 24 * 7:
            minutes = 60 * 24 * 7
        return minutes

    def get_active_share_or_404(token: str) -> ShareLink:
        link = ShareLink.query.filter_by(token=token).first_or_404()
        if link.revoked_at is not None:
            abort(404)
        if link.expires_at <= datetime.utcnow():
            abort(404)
        return link

    @app.post("/share")
    @login_required
    def create_share():
        if current_user.is_admin:
            abort(403)

        item_type = (request.form.get("item_type") or "").strip().lower()
        item_id_raw = (request.form.get("item_id") or "").strip()
        minutes = parse_share_minutes(request.form.get("minutes"))
        try:
            item_id = int(item_id_raw)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "Invalid item."}), 400

        if item_type not in {"file", "folder"}:
            return jsonify({"ok": False, "error": "Invalid item type."}), 400

        if item_type == "file":
            vf = VaultFile.query.filter_by(id=item_id).first()
            if not vf or vf.user_id != current_user.id:
                return jsonify({"ok": False, "error": "File not found."}), 404
        else:
            folder = Folder.query.filter_by(id=item_id, user_id=current_user.id).first()
            if not folder or folder.name == ROOT_FOLDER_NAME:
                return jsonify({"ok": False, "error": "Folder not found."}), 404

        token = uuid.uuid4().hex
        expires_at = datetime.utcnow() + timedelta(minutes=minutes)
        link = ShareLink(
            user_id=current_user.id,
            token=token,
            item_type=item_type,
            item_id=item_id,
            expires_at=expires_at,
        )
        db.session.add(link)
        db.session.commit()

        return jsonify(
            {
                "ok": True,
                "share": {
                    "id": link.id,
                    "token": link.token,
                    "url": build_public_share_url(link.token),
                    "expires_at": link.expires_at.strftime("%Y-%m-%d %H:%M"),
                    "minutes": minutes,
                    "item_type": link.item_type,
                    "item_id": link.item_id,
                },
            }
        )

    @app.get("/s/<token>")
    def shared_access(token: str):
        link = get_active_share_or_404(token)
        if link.item_type == "file":
            vf = VaultFile.query.filter_by(id=link.item_id, user_id=link.user_id).first_or_404()
            target_path = os.path.join(app.config["UPLOAD_ROOT"], str(vf.user_id), str(vf.folder_id), vf.stored_filename)
            if not os.path.exists(target_path):
                abort(404)
            return send_file(
                target_path,
                as_attachment=True,
                download_name=vf.original_filename,
                mimetype=vf.content_type or "application/octet-stream",
            )

        folder = Folder.query.filter_by(id=link.item_id, user_id=link.user_id).first_or_404()
        if folder.name == ROOT_FOLDER_NAME:
            abort(404)
        files = VaultFile.query.filter_by(user_id=link.user_id, folder_id=folder.id).order_by(VaultFile.uploaded_at.desc())
        return render_template(
            "shared_folder.html",
            share=link,
            folder=folder,
            files=files,
            token=token,
        )

    @app.get("/s/<token>/file/<int:file_id>/download")
    def shared_folder_download(token: str, file_id: int):
        link = get_active_share_or_404(token)
        if link.item_type != "folder":
            abort(404)

        vf = VaultFile.query.filter_by(id=file_id, user_id=link.user_id, folder_id=link.item_id).first_or_404()
        target_path = os.path.join(app.config["UPLOAD_ROOT"], str(vf.user_id), str(vf.folder_id), vf.stored_filename)
        if not os.path.exists(target_path):
            abort(404)
        return send_file(
            target_path,
            as_attachment=True,
            download_name=vf.original_filename,
            mimetype=vf.content_type or "application/octet-stream",
        )

    @app.get("/shared")
    @login_required
    def shared_links():
        if current_user.is_admin:
            abort(403)
        now = datetime.utcnow()
        links = (
            ShareLink.query.filter_by(user_id=current_user.id)
            .order_by(ShareLink.created_at.desc())
            .all()
        )

        rows = []
        for link in links:
            status = "active"
            if link.revoked_at is not None:
                status = "revoked"
            elif link.expires_at <= now:
                status = "expired"

            item_name = "-"
            if link.item_type == "file":
                vf = VaultFile.query.filter_by(id=link.item_id, user_id=current_user.id).first()
                if vf:
                    item_name = vf.original_filename
            else:
                folder = Folder.query.filter_by(id=link.item_id, user_id=current_user.id).first()
                if folder:
                    item_name = folder.name

            rows.append(
                {
                    "id": link.id,
                    "item_type": link.item_type,
                    "item_id": link.item_id,
                    "item_name": item_name,
                    "created_at": link.created_at.strftime("%Y-%m-%d %H:%M"),
                    "expires_at": link.expires_at.strftime("%Y-%m-%d %H:%M"),
                    "revoked_at": link.revoked_at.strftime("%Y-%m-%d %H:%M") if link.revoked_at else "",
                    "status": status,
                    "url": build_public_share_url(link.token),
                }
            )

        return render_template("shared_links.html", rows=rows)

    @app.post("/shared/<int:share_id>/revoke")
    @login_required
    def revoke_share(share_id: int):
        if current_user.is_admin:
            abort(403)
        link = ShareLink.query.filter_by(id=share_id, user_id=current_user.id).first_or_404()
        db.session.delete(link)
        db.session.commit()
        if wants_json(request):
            return jsonify({"ok": True})
        return redirect(url_for("shared_links"))

    @app.get("/search")
    @login_required
    def search():
        if current_user.is_admin:
            abort(403)

        q = (request.args.get("q") or "").strip()
        ext = (request.args.get("ext") or "").strip().lstrip(".")
        filetype = (request.args.get("filetype") or "").strip()
        date_from = (request.args.get("date_from") or "").strip()
        date_to = (request.args.get("date_to") or "").strip()

        results = []
        if q or ext or filetype or date_from or date_to:
            query = (
                db.session.query(VaultFile, Folder)
                .join(Folder, VaultFile.folder_id == Folder.id)
                .filter(VaultFile.user_id == current_user.id)
            )

            if q:
                query = query.filter(VaultFile.original_filename.ilike(f"%{q}%"))
            if ext:
                query = query.filter(VaultFile.original_filename.ilike(f"%.{ext}"))
            if filetype:
                query = query.filter(VaultFile.content_type.ilike(f"%{filetype}%"))

            df = parse_date_yyyy_mm_dd(date_from)
            if df:
                query = query.filter(VaultFile.uploaded_at >= datetime(df.year, df.month, df.day))

            dt = parse_date_yyyy_mm_dd(date_to)
            if dt:
                query = query.filter(VaultFile.uploaded_at <= datetime(dt.year, dt.month, dt.day, 23, 59, 59))

            results = query.order_by(VaultFile.uploaded_at.desc()).limit(200).all()

        if wants_json(request):
            payload = []
            for vf, folder in results[:50]:
                folder_label = folder.name
                if folder_label == ROOT_FOLDER_NAME:
                    folder_label = "Vault (root)"
                payload.append(
                    {
                        "id": vf.id,
                        "name": vf.original_filename,
                        "content_type": vf.content_type,
                        "size_bytes": int(vf.size_bytes or 0),
                        "uploaded_at": vf.uploaded_at.strftime("%Y-%m-%d %H:%M"),
                        "folder": {"id": folder.id, "name": folder_label},
                        "download_url": url_for("download", file_id=vf.id),
                        "open_folder_url": url_for("dashboard")
                        if folder.name == ROOT_FOLDER_NAME
                        else url_for("folder_view", folder_id=folder.id),
                    }
                )
            return jsonify({"ok": True, "q": q, "results": payload})

        return render_template(
            "search.html",
            q=q,
            ext=ext,
            filetype=filetype,
            date_from=date_from,
            date_to=date_to,
            results=results,
        )

    @app.post("/folders")
    @login_required
    def create_folder():
        if current_user.is_admin:
            abort(403)
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("Folder name is required.", "error")
            if wants_json(request):
                return jsonify({"ok": False, "error": "Folder name is required."}), 400
            return redirect(url_for("dashboard"))

        if name == ROOT_FOLDER_NAME:
            flash("Folder name is not allowed.", "error")
            if wants_json(request):
                return jsonify({"ok": False, "error": "Folder name is not allowed."}), 400
            return redirect(url_for("dashboard"))

        folder = Folder(user_id=current_user.id, name=name)
        db.session.add(folder)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("Folder name already exists.", "error")
            if wants_json(request):
                return jsonify({"ok": False, "error": "Folder name already exists."}), 400
            return redirect(url_for("dashboard"))

        if wants_json(request):
            return jsonify(
                {
                    "ok": True,
                    "folder": {
                        "id": folder.id,
                        "name": folder.name,
                        "created_at": folder.created_at.strftime("%Y-%m-%d %H:%M"),
                        "is_bookmarked": bool(folder.is_bookmarked),
                    },
                }
            )

        return redirect(url_for("folder_view", folder_id=folder.id))

    @app.post("/folder/<int:folder_id>/bookmark")
    @login_required
    def bookmark_folder(folder_id: int):
        if current_user.is_admin:
            abort(403)
        folder = Folder.query.filter_by(id=folder_id, user_id=current_user.id).first_or_404()
        folder.is_bookmarked = True
        db.session.commit()

        if wants_json(request):
            return jsonify({"ok": True, "folder_id": folder.id, "name": folder.name, "is_bookmarked": True})

        next_url = request.form.get("next") or request.referrer or url_for("dashboard")
        return redirect(next_url)

    @app.post("/folder/<int:folder_id>/rename")
    @login_required
    def rename_folder(folder_id: int):
        if current_user.is_admin:
            abort(403)
        folder = Folder.query.filter_by(id=folder_id, user_id=current_user.id).first_or_404()
        if folder.name == ROOT_FOLDER_NAME:
            abort(403)

        new_name = (request.form.get("name") or "").strip()
        if not new_name:
            if wants_json(request):
                return jsonify({"ok": False, "error": "Folder name is required."}), 400
            flash("Folder name is required.", "error")
            return redirect(request.referrer or url_for("dashboard"))

        if new_name == ROOT_FOLDER_NAME:
            if wants_json(request):
                return jsonify({"ok": False, "error": "Folder name is not allowed."}), 400
            flash("Folder name is not allowed.", "error")
            return redirect(request.referrer or url_for("dashboard"))

        folder.name = new_name
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            if wants_json(request):
                return jsonify({"ok": False, "error": "Folder name already exists."}), 400
            flash("Folder name already exists.", "error")
            return redirect(request.referrer or url_for("dashboard"))

        if wants_json(request):
            return jsonify({"ok": True, "folder": {"id": folder.id, "name": folder.name, "is_bookmarked": bool(folder.is_bookmarked)}})

        return redirect(url_for("folder_view", folder_id=folder.id))

    @app.post("/folder/<int:folder_id>/delete")
    @login_required
    def delete_folder(folder_id: int):
        if current_user.is_admin:
            abort(403)
        folder = Folder.query.filter_by(id=folder_id, user_id=current_user.id).first_or_404()
        if folder.name == ROOT_FOLDER_NAME:
            abort(403)

        files = VaultFile.query.filter_by(user_id=current_user.id, folder_id=folder.id).all()
        for vf in files:
            path = file_disk_path(app.config["UPLOAD_ROOT"], vf.user_id, vf.folder_id, vf.stored_filename)
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass
            db.session.delete(vf)

        folder_path = os.path.join(app.config["UPLOAD_ROOT"], str(current_user.id), str(folder.id))
        try:
            if os.path.isdir(folder_path):
                for root, _dirs, filenames in os.walk(folder_path, topdown=False):
                    for fn in filenames:
                        try:
                            os.remove(os.path.join(root, fn))
                        except OSError:
                            pass
                try:
                    os.rmdir(folder_path)
                except OSError:
                    pass
        except OSError:
            pass

        db.session.delete(folder)
        db.session.commit()

        if wants_json(request):
            return jsonify({"ok": True, "folder_id": folder_id})

        return redirect(url_for("dashboard"))

    @app.post("/folder/<int:folder_id>/unbookmark")
    @login_required
    def unbookmark_folder(folder_id: int):
        if current_user.is_admin:
            abort(403)
        folder = Folder.query.filter_by(id=folder_id, user_id=current_user.id).first_or_404()
        folder.is_bookmarked = False
        db.session.commit()

        if wants_json(request):
            return jsonify({"ok": True, "folder_id": folder.id, "name": folder.name, "is_bookmarked": False})

        next_url = request.form.get("next") or request.referrer or url_for("dashboard")
        return redirect(next_url)

    @app.post("/upload")
    @login_required
    def upload_any():
        if current_user.is_admin:
            abort(403)

        folder_id = request.form.get("folder_id")
        try:
            folder_id_int = int(folder_id)
        except (TypeError, ValueError):
            flash("Select a folder.", "error")
            if wants_json(request):
                return jsonify({"ok": False, "error": "Select a folder."}), 400
            return redirect(url_for("dashboard"))

        folder = Folder.query.filter_by(id=folder_id_int, user_id=current_user.id).first()
        if not folder:
            flash("Folder not found.", "error")
            if wants_json(request):
                return jsonify({"ok": False, "error": "Folder not found."}), 404
            return redirect(url_for("dashboard"))

        if "file" not in request.files:
            flash("No file provided.", "error")
            if wants_json(request):
                return jsonify({"ok": False, "error": "No file provided."}), 400
            return redirect(url_for("dashboard"))

        f = request.files["file"]
        if not f or not f.filename:
            flash("No file selected.", "error")
            if wants_json(request):
                return jsonify({"ok": False, "error": "No file selected."}), 400
            return redirect(url_for("dashboard"))

        original = f.filename
        safe_name = secure_filename(original)
        stored = f"{uuid.uuid4().hex}__{safe_name or 'file'}"

        target_dir = os.path.join(app.config["UPLOAD_ROOT"], str(current_user.id), str(folder.id))
        os.makedirs(target_dir, exist_ok=True)
        target_path = os.path.join(target_dir, stored)

        f.save(target_path)

        size_bytes = 0
        try:
            size_bytes = os.path.getsize(target_path)
        except OSError:
            size_bytes = 0

        record = VaultFile(
            user_id=current_user.id,
            folder_id=folder.id,
            original_filename=original,
            stored_filename=stored,
            content_type=f.mimetype,
            size_bytes=size_bytes,
        )
        db.session.add(record)
        db.session.commit()

        flash("Uploaded successfully.", "success")
        if wants_json(request):
            return jsonify(
                {
                    "ok": True,
                    "file": {
                        "id": record.id,
                        "folder_id": folder.id,
                        "original_filename": record.original_filename,
                        "content_type": record.content_type,
                        "size_bytes": record.size_bytes,
                        "uploaded_at": record.uploaded_at.strftime("%Y-%m-%d %H:%M"),
                    },
                }
            )
        return redirect(url_for("folder_view", folder_id=folder.id))

    @app.get("/folder/<int:folder_id>")
    @login_required
    def folder_view(folder_id: int):
        if current_user.is_admin:
            abort(403)
        folder = Folder.query.filter_by(id=folder_id, user_id=current_user.id).first_or_404()
        if folder.name == ROOT_FOLDER_NAME:
            return redirect(url_for("dashboard"))
        root_folder = get_or_create_root_folder(current_user.id)
        files = VaultFile.query.filter_by(folder_id=folder.id, user_id=current_user.id).order_by(
            VaultFile.uploaded_at.desc()
        )
        breadcrumbs = [("Vault", url_for("dashboard")), (folder.name, url_for("folder_view", folder_id=folder.id))]
        return render_template(
            "explorer.html",
            breadcrumbs=breadcrumbs,
            selected_folder=folder,
            selected_folder_id=folder.id,
            folders=[],
            files=files,
            root_folder_id=root_folder.id,
        )

    @app.post("/folder/<int:folder_id>/upload")
    @login_required
    def upload_file(folder_id: int):
        if current_user.is_admin:
            abort(403)
        folder = Folder.query.filter_by(id=folder_id, user_id=current_user.id).first_or_404()

        if "file" not in request.files:
            flash("No file provided.", "error")
            if wants_json(request):
                return jsonify({"ok": False, "error": "No file provided."}), 400
            return redirect(url_for("folder_view", folder_id=folder.id))

        f = request.files["file"]
        if not f or not f.filename:
            flash("No file selected.", "error")
            if wants_json(request):
                return jsonify({"ok": False, "error": "No file selected."}), 400
            return redirect(url_for("folder_view", folder_id=folder.id))

        original = f.filename
        safe_name = secure_filename(original)
        stored = f"{uuid.uuid4().hex}__{safe_name or 'file'}"

        target_dir = os.path.join(app.config["UPLOAD_ROOT"], str(current_user.id), str(folder.id))
        os.makedirs(target_dir, exist_ok=True)
        target_path = os.path.join(target_dir, stored)

        f.save(target_path)

        size_bytes = 0
        try:
            size_bytes = os.path.getsize(target_path)
        except OSError:
            size_bytes = 0

        record = VaultFile(
            user_id=current_user.id,
            folder_id=folder.id,
            original_filename=original,
            stored_filename=stored,
            content_type=f.mimetype,
            size_bytes=size_bytes,
        )
        db.session.add(record)
        db.session.commit()

        flash("Uploaded successfully.", "success")
        if wants_json(request):
            return jsonify(
                {
                    "ok": True,
                    "file": {
                        "id": record.id,
                        "folder_id": folder.id,
                        "original_filename": record.original_filename,
                        "content_type": record.content_type,
                        "size_bytes": record.size_bytes,
                        "uploaded_at": record.uploaded_at.strftime("%Y-%m-%d %H:%M"),
                    },
                }
            )
        return redirect(url_for("folder_view", folder_id=folder.id))

    @app.get("/file/<int:file_id>/download")
    @login_required
    def download(file_id: int):
        vf = VaultFile.query.filter_by(id=file_id).first_or_404()
        if not current_user.is_admin and vf.user_id != current_user.id:
            abort(403)

        target_path = os.path.join(app.config["UPLOAD_ROOT"], str(vf.user_id), str(vf.folder_id), vf.stored_filename)
        if not os.path.exists(target_path):
            abort(404)

        return send_file(
            target_path,
            as_attachment=True,
            download_name=vf.original_filename,
            mimetype=vf.content_type or "application/octet-stream",
        )

    @app.post("/file/<int:file_id>/rename")
    @login_required
    def rename_file(file_id: int):
        vf = VaultFile.query.filter_by(id=file_id).first_or_404()
        if not current_user.is_admin and vf.user_id != current_user.id:
            abort(403)

        new_name = (request.form.get("name") or "").strip()
        if not new_name:
            if wants_json(request):
                return jsonify({"ok": False, "error": "File name is required."}), 400
            flash("File name is required.", "error")
            return redirect(request.referrer or url_for("dashboard"))

        vf.original_filename = new_name
        db.session.commit()

        if wants_json(request):
            return jsonify({"ok": True, "file": {"id": vf.id, "original_filename": vf.original_filename}})

        return redirect(request.referrer or url_for("dashboard"))

    @app.post("/file/<int:file_id>/delete")
    @login_required
    def delete_file(file_id: int):
        vf = VaultFile.query.filter_by(id=file_id).first_or_404()
        if not current_user.is_admin and vf.user_id != current_user.id:
            abort(403)

        path = file_disk_path(app.config["UPLOAD_ROOT"], vf.user_id, vf.folder_id, vf.stored_filename)
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass

        db.session.delete(vf)
        db.session.commit()

        if wants_json(request):
            return jsonify({"ok": True, "file_id": file_id})

        return redirect(request.referrer or url_for("dashboard"))

    @app.get("/admin")
    @admin_required
    def admin_dashboard():
        users = User.query.order_by(User.created_at.desc()).all()
        return render_template("admin_dashboard.html", users=users)

    @app.get("/admin/user/<int:user_id>")
    @admin_required
    def admin_user(user_id: int):
        user = User.query.filter_by(id=user_id).first_or_404()
        folders = Folder.query.filter_by(user_id=user.id).order_by(Folder.created_at.desc()).all()
        file_count = VaultFile.query.filter_by(user_id=user.id).count()
        total_bytes = db.session.query(db.func.coalesce(db.func.sum(VaultFile.size_bytes), 0)).filter(
            VaultFile.user_id == user.id
        ).scalar()
        return render_template(
            "admin_user.html",
            user=user,
            folders=folders,
            file_count=file_count,
            total_bytes=int(total_bytes or 0),
        )

    @app.get("/admin/folder/<int:folder_id>")
    @admin_required
    def admin_folder(folder_id: int):
        folder = Folder.query.filter_by(id=folder_id).first_or_404()
        user = User.query.filter_by(id=folder.user_id).first_or_404()
        files = VaultFile.query.filter_by(folder_id=folder.id, user_id=user.id).order_by(VaultFile.uploaded_at.desc())
        return render_template("admin_folder.html", user=user, folder=folder, files=files)

    return app


def ensure_default_admin():
    username = os.environ.get("ADMIN_USERNAME")
    password = os.environ.get("ADMIN_PASSWORD")
    if not username or not password:
        return

    existing = User.query.filter_by(username=username).first()
    if existing:
        if not existing.is_admin:
            existing.is_admin = True
            db.session.commit()
        return

    user = User(username=username, password_hash=generate_password_hash(password), is_admin=True)
    db.session.add(user)
    db.session.commit()


def ensure_default_folders_for_user(user_id: int):
    get_or_create_root_folder(user_id)
    existing_names = {
        row[0]
        for row in Folder.query.filter_by(user_id=user_id).with_entities(Folder.name).all()
    }

    created = False
    for name in DEFAULT_FOLDERS:
        if name in existing_names:
            continue
        db.session.add(Folder(user_id=user_id, name=name, is_bookmarked=True))
        created = True

    if created:
        db.session.commit()


def get_or_create_root_folder(user_id: int) -> Folder:
    folder = Folder.query.filter_by(user_id=user_id, name=ROOT_FOLDER_NAME).first()
    if folder:
        return folder

    folder = Folder(user_id=user_id, name=ROOT_FOLDER_NAME, is_bookmarked=False)
    db.session.add(folder)
    db.session.commit()
    return folder


def ensure_default_folders_for_all_users():
    user_ids = [row[0] for row in User.query.with_entities(User.id).all()]
    for uid in user_ids:
        ensure_default_folders_for_user(uid)


def parse_date_yyyy_mm_dd(value: str) -> date | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def ensure_schema():
    try:
        cols = [row[1] for row in db.session.execute(db.text("PRAGMA table_info(folder)")).fetchall()]
    except Exception:
        return

    if "is_bookmarked" not in cols:
        db.session.execute(db.text("ALTER TABLE folder ADD COLUMN is_bookmarked BOOLEAN NOT NULL DEFAULT 0"))
        db.session.commit()


def wants_json(req) -> bool:
    if (req.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return True
    accept = (req.headers.get("Accept") or "").lower()
    if "application/json" in accept:
        return True
    return (req.args.get("format") or "").lower() == "json"


app = create_app()
