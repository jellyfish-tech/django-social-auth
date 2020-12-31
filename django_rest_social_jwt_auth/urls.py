from django.urls import path
from .views import signin_facebook, fb_callback, signin_github, gh_callback, signin_google, goo_callback

urlpatterns = [
    path('facebook/', signin_facebook, name='facebook_login'),
    path('fb/', fb_callback, name='fb_callback'),
    path('github/', signin_github, name='github_login'),
    path('gh/', gh_callback, name='gh_callback'),
    path('google/', signin_google, name='google_login'),
    path('goo/', goo_callback, name='goo_callback')
]
