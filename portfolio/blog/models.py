from django.db import models

# Create your models here.


class Category(models.Model):
    name = models.CharField(max_length=30)
    slug = models.SlugField(unique=True)

    class Meta:
        verbose_name_plural = "categories"
        ordering = ['name']
        unique_together = ('name', 'slug')

    def save(self, *args, **kwargs):
        self.slug = self.name.replace(' ', '-').lower()
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return f"/blog/{self.slug}"

    def __str__(self):
        return self.name


class Post(models.Model):
    title = models.CharField(max_length=255)
    body = models.TextField()
    picture = models.ImageField(
        upload_to='uploads/posts/% Y/% m/', blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    categories = models.ManyToManyField("Category", related_name="posts")
    slug = models.SlugField(unique=True)

    def save(self, *args, **kwargs):
        self.slug = self.title.replace(' ', '-').lower()
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return f"/blog/{self.slug}"

    class Meta:
        verbose_name_plural = "posts"
        ordering = ['-created_on']
        unique_together = ('title', 'slug')
        get_latest_by = 'created_on'

    def __str__(self):
        return self.title

    ################################################################

    def get_comments(self):
        return Comment.objects.filter(post=self)

    def get_category_list(self):
        return ', '.join([str(c) for c in self.categories.all()])

    def get_category_count(self):
        return self.categories.count()

    def get_category_ids(self):
        return [c.id for c in self.categories.all()]

    def get_comment_count(self):
        return Comment.objects.filter(post=self).count()

    def get_comment_average_rating(self):
        total_rating = sum([c.rating for c in self.get_comments()])
        if total_rating:
            return total_rating / self.get_comment_count()
        else:
            return 0.0

    def get_comment_rating_distribution(self):
        ratings = [c.rating for c in self.get_comments()]
        if ratings:
            rating_counts = {i: ratings.count(i) for i in set(ratings)}
            return rating_counts
        else:
            return {}

    def get_comment_rating_averages(self):
        rating_distribution = self.get_comment_rating_distribution()
        if rating_distribution:
            return {rating: rating_distribution[rating] / self.get_comment_count() for rating in rating_distribution}
        else:
            return {}

    def get_comment_rating_highest_rated(self):
        highest_rated_comment = max(
            self.get_comments(), key=lambda c: c.rating)
        if highest_rated_comment:
            return f"{highest_rated_comment.author} rated {highest_rated_comment.rating} on '{highest_rated_comment.post}'"
        else:
            return "No comments found"

    ################################################################


class Comment(models.Model):
    author = models.CharField(max_length=60)
    body = models.TextField()
    created_on = models.DateTimeField(auto_now_add=True)
    post = models.ForeignKey("Post", on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.author} on '{self.post}'"
