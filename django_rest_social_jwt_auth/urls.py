from django.urls import path

from .views import (fb_callback, gh_callback, github_refresh, goo_callback,
                    google_refresh, signin_facebook, signin_github,
                    signin_google, social_logout)

urlpatterns = [
    path('facebook/', signin_facebook, name='facebook_login'),
    path('fb/', fb_callback, name='fb_callback'),
    path('github/', signin_github, name='github_login'),
    path('gh/', gh_callback, name='gh_callback'),
    path('google/', signin_google, name='google_login'),
    path('goo/', goo_callback, name='goo_callback'),
    path('social_logout/', social_logout, name='social_logout'),
    path('google_refresh/', google_refresh, name='google_refresh'),
    path('github_refresh/', github_refresh, name='github_refresh')
]
