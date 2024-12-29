from django.shortcuts import render

# Create your views here.


def blogs_list(request):
    """
    View function for blog list page
    """

    return render(request, 'blog/list.html')
