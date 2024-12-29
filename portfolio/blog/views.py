from django.shortcuts import render
from .models import Post, Category, Comment

# Create your views here.


def blogs_list(request):
    """
    View function for blog list page
    """

    # Fetch all blog posts from the database
    posts = Post.objects.all('-created_on')

    # Fetch all categories from the database
    categories = Category.objects.all()

    # Render the blog list template with the fetched data
    return render(request, 'blogs/list.html', {
        'posts': posts,
        'categories': categories,
    })

    # TODO: Add pagination, filtering, and search functionality here


def blog_detail(request, slug):
    """
    View function for blog detail page
    """
    # Fetch the blog post with the given slug from the database
    post = Post.objects.get(slug=slug)

    # Fetch all comments for the blog post from the database
    comments = Comment.objects.filter(post=post)

    # Render the blog detail template with the fetched data
    return render(request, 'blogs/detail.html', {
        'post': post,
        'comments': comments,
    })

    # TODO: Add functionality to allow users to comment on the blog post and display the comments in the detail page
    # TODO: Add functionality to allow users to like or dislike the blog post and display the number of likes in the detail page
    # TODO: Add functionality to allow users to edit or delete their own comments on the blog post
    # TODO: Add functionality to display the previous and next blog posts in the list page
    # TODO: Add functionality to allow users to subscribe to the blog and receive email notifications about new posts and comments
    # TODO: Add functionality to allow users to share the blog post on social media platforms with a customizable message
    # TODO: Add functionality to allow users to report inappropriate content or spam comments
    # TODO: Add functionality to allow users to rate the blog post and display the average rating in the detail page
    # TODO: Add functionality to allow users to bookmark or save the blog post for later reference
    # TODO: Add functionality to allow users to flag inappropriate content or spam comments for moderation


def category_detail(request, slug):
    """
    View function for category detail page
    """
    # Fetch the category with the given slug from the database
    category = Category.objects.get(slug=slug)

    # Fetch all blog posts belonging to the category from the database
    posts = Post.objects.filter(category=category)

    # Render the category detail template with the fetched data
    return render(request, 'blogs/category_detail.html', {
        'category': category,
        'posts': posts,
    })

    # TODO: Add pagination, filtering, and search functionality here
    # TODO: Add functionality to display the number of blog posts in the category in the category detail page
    # TODO: Add functionality to display the previous and next categories in the list page
    # TODO: Add functionality to allow users to subscribe to the blog and receive email notifications about new posts and comments in the category
    # TODO: Add functionality to allow users to share the blog posts in the category on social media platforms with a customizable message
    # TODO: Add functionality to allow users to report inappropriate content or spam comments in the category
    # TODO: Add functionality to allow users to rate the blog posts in the category and display the average rating in the category detail page
    # TODO: Add functionality to allow users to bookmark or save the blog posts in the category for later reference
    # TODO: Add functionality to allow users to flag inappropriate content or spam comments for moderation


def search(request):
    """
    View function for search results page
    """
    # Fetch the search query from the request
    query = request.GET.get('q')

    # Fetch all blog posts containing the search query from the database
    posts = Post.objects.filter(title__icontains=query)

    # Render the search results template with the fetched data
    return render(request, 'blogs/search_results.html', {
        'query': query,
        'posts': posts,
    })

    # TODO: Add pagination, filtering, and search functionality here
    # TODO: Add functionality to display the number of blog posts matching the search query in the search results page
    # TODO: Add functionality to display the previous and next blog posts in the search results page
    # TODO: Add functionality to allow users to subscribe to the blog and receive email notifications about new posts and comments matching the search query
