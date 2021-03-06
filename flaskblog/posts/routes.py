from flask import Blueprint
from flask import (render_template, url_for, flash, redirect, request, abort)
from flask_login import current_user, login_required
from flaskblog import db
from flaskblog.models import Post
from flaskblog.posts.forms import PostForm
import bleach




posts = Blueprint('posts', __name__)


@posts.route("/post/new", methods=["GET","POST"])
@login_required
def new_post():
	form = PostForm()
	if form.validate_on_submit():
		post = Post(title=form.title.data, content=form.content.data, author=current_user)
		db.session.add(post)
		db.session.commit()
		flash("Your post has been posted successfully", "success")
		return redirect(url_for('main.home'))
	return	render_template("create_post.html", title="New Post", form=form, legend="New Post")


@posts.route("/post/int:<post_id>")
def post(post_id):
	post = Post.query.get_or_404(post_id)
	return	render_template("post.html", title=post.title, post=post)

@posts.route("/post/int:<post_id>/update", methods=["GET","POST"])
@login_required
def update_post(post_id):
	post = Post.query.get_or_404(post_id)
	if post.author != current_user:
		abort(403)
	form = PostForm()
	if request.method == 'GET':
		form.title.data = post.title
		form.content.data = post.content
	elif form.validate_on_submit:
		post.title = form.title.data
		post.content = form.content.data
		post.approve_flag = False
		db.session.commit()
		flash("Your post has been updated successfully","success")
		return redirect(url_for('posts.post', post_id=post.id))
	
	return	render_template("create_post.html", title="Update Post", form=form , legend="Update Post")

@posts.route("/post/int:<post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
	post = Post.query.get_or_404(post_id)
	if post.author != current_user and current_user.username!="admin@admin.com":
		abort(403)

	db.session.delete(post)
	db.session.commit()
	flash("Your post has been deleted successfully","success")
	return redirect(url_for('main.home'))

@posts.route("/post/int:<post_id>/approve", methods=["GET","POST"])
@login_required
def approve_post(post_id):
	post = Post.query.get_or_404(post_id)
	if current_user.username=="admin@admin.com" and post.approve_flag==False:
		form = PostForm()
		if form.validate_on_submit:
			post.approve_flag = True
		db.session.commit()
		flash("The post has been successfully approved","success")
		return redirect(url_for('main.home'))
	return	render_template("post.html", title=post.title, post=post)

@posts.route("/post/int:<post_id>/disapprove", methods=["GET","POST"])
@login_required
def disapprove_post(post_id):
	post = Post.query.get_or_404(post_id)
	if current_user.username=="admin@admin.com" and post.approve_flag==True:
		form = PostForm()
		if form.validate_on_submit:
			post.approve_flag = False
		db.session.commit()
		flash("The post has been successfully disapproved","success")
		return redirect(url_for('main.home'))
	return	render_template("post.html", title=post.title, post=post)



