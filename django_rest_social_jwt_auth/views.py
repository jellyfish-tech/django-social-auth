from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib.auth.hashers import make_password
from requests_oauthlib import OAuth2Session
from requests_oauthlib.compliance_fixes import facebook_compliance_fix
from .models import SocialUser
from datetime import datetime, timedelta
import json
import jwt
from django.contrib.auth import login, logout
from django.http.response import JsonResponse
import requests


def create_jwt(user):
    token = jwt.encode({
        'role': settings.JWT_ROLE,
        'userid': str(user.id),
        'exp': (datetime.now() + timedelta(minutes=settings.JWT_EXP)).timestamp(),
    }, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return {'token': token}

def user_busines(social_data: dict, social_organisation):
    social_user_id = social_data.get('id')
    social_user = SocialUser.objects.filter(social_id=social_user_id, social_organisation=social_organisation).first()
    social_data = social_data.get('token')
    social_refresh_token = social_data.get('refresh_token', '')
    social_token = social_data['access_token']
    if not social_user:
        social_user_name = social_data.get('name') or social_data.get('login')
        social_user_password = make_password(password=None)
        social_user = get_user_model().objects.create(username=social_user_name, password=social_user_password)

        social_user.socialuser = SocialUser(user=social_user, social_organisation=social_organisation,
                                            social_id=social_user_id, token=social_token,
                                            refresh_token=social_refresh_token)
        social_user.socialuser.save()
    else:
        social_user.token = social_token
        social_user.refresh_token = social_refresh_token
        social_user.save()
        social_user = social_user.user
    return social_user

def updating_token(user, token):
    user.socialuser.token = token
    user.socialuser.save()
    return True

def is_auth_social(request):
    user = request.user
    if user.is_authenticated:
        if hasattr(user, 'socialuser'):
            provider = user.socialuser.social_organisation
            return provider
        else:
            return False
    return None

def social_logout(request):
    if request.user.is_authenticated:
        user = request.user
        logout(request)
        try:
            del request.session['jwt']
        except KeyError:
            pass
        user.socialuser.token = ''
        user.socialuser.save()
    return redirect(settings.LOGOUT_URL)

def get_token(request=None, user=None):
    if request:
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({'token': ''}, status=401)
    elif user:
        user = user
    else:
        raise AttributeError('either request or user instance is requeired')

    token = user.socialuser.token
    if token:
        return JsonResponse({'token': token}, status=200)
    return JsonResponse({'token': ''}, status=404)

def get_refresh_token(request=None, user=None):
    if request:
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({'refresh_token': ''}, status=401)
    elif user:
        user = user
    refresh_token = user.socialuser.refresh_token
    if refresh_token:
        return JsonResponse({'refresh_token': refresh_token}, status=200)
    return JsonResponse({'refresh_token': ''}, status=404)


def signin_facebook(request):
    client_id = settings.FB_CLIENT_ID
    redirect_uri = request.build_absolute_uri(reverse(fb_callback))
    base_url = 'https://www.facebook.com/v9.0/dialog/oauth?'

    fb = OAuth2Session(client_id, redirect_uri=redirect_uri)
    fb = facebook_compliance_fix(fb)

    authorization_url, state = fb.authorization_url(base_url)
    return redirect(authorization_url)

def fb_callback(request):
    client_id = settings.FB_CLIENT_ID
    client_secret = settings.FB_CLIENT_SECRET
    redirect_uri = request.build_absolute_uri(reverse(fb_callback))
    token_url = 'https://graph.facebook.com/v9.0/oauth/access_token?'

    fb = OAuth2Session(client_id, redirect_uri=redirect_uri)
    token = fb.fetch_token(token_url, client_secret=client_secret, authorization_response=request.build_absolute_uri())
    response = fb.get('https://graph.facebook.com/me?').json()
    response['token'] = token
    user = user_busines(response, 'facebook')
    user_jwt = create_jwt(user)
    login(request, user)
    request.session['jwt'] = json.dumps(user_jwt)
    return redirect(settings.AUTHED_URL)


def signin_github(request):
    base_url = 'https://github.com/login/oauth/authorize'
    redirect_uri = request.build_absolute_uri(reverse(gh_callback))
    client_id = settings.GH_CLIENT_ID

    gh = OAuth2Session(client_id, redirect_uri=redirect_uri)

    authorization_url, state = gh.authorization_url(base_url, prompt="select_account")
    return redirect(authorization_url)

def gh_callback(request):
    token_url = 'https://github.com/login/oauth/access_token'
    redirect_uri = request.build_absolute_uri(reverse(gh_callback))

    client_secret = settings.GH_CLIENT_SECRET
    client_id = settings.GH_CLIENT_ID

    gh = OAuth2Session(client_id, redirect_uri=redirect_uri)
    token = gh.fetch_token(token_url, client_secret=client_secret, authorization_response=request.build_absolute_uri())
    response = gh.get('https://api.github.com/user').json()
    response['token'] = token
    print(response)
    user = user_busines(response, 'github')
    user_jwt = create_jwt(user)
    login(request, user)
    request.session['jwt'] = json.dumps(user_jwt)
    return redirect(settings.AUTHED_URL)

def github_refresh(request=None, user=None):
    if request:
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({'status': ''}, status=401)
    elif user:
        user = user
    refresh_token = user.socialuser.refresh_token
    if refresh_token:
        client_secret = settings.GH_CLIENT_SECRET
        client_id = settings.GH_CLIENT_ID
        token_url = 'https://github.com/login/oauth/access_token'
        response = requests.post(token_url, params={'grant_type': 'refresh_token'}, data={
            'client_id': client_id, 'client_secret': client_secret, 'refresh_token': refresh_token
        }).json()
        updating_token(user, token=response['access_token'])
        return JsonResponse({'status': 'refreshed'}, status=200)
    return JsonResponse({'status': ''}, status=404)


def signin_google(request):
    base_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    redirect_uri = request.build_absolute_uri(reverse(goo_callback))
    client_id = settings.GOO_CLIENT_ID
    scope = [
        "https://www.googleapis.com/auth/userinfo.profile",
    ]

    goo = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)

    authorization_url, state = goo.authorization_url(base_url, access_type="offline", prompt="select_account")
    return redirect(authorization_url)

def goo_callback(request):
    token_url = 'https://www.googleapis.com/oauth2/v4/token'
    redirect_uri = request.build_absolute_uri(reverse(goo_callback))

    client_secret = settings.GOO_CLIENT_SECRET
    client_id = settings.GOO_CLIENT_ID

    goo = OAuth2Session(client_id, redirect_uri=redirect_uri)
    token = goo.fetch_token(token_url, client_secret=client_secret, authorization_response=request.build_absolute_uri())
    response = goo.get('https://www.googleapis.com/oauth2/v1/userinfo').json()
    response['token'] = token
    user = user_busines(response, 'google')
    user_jwt = create_jwt(user)
    login(request, user)
    request.session['jwt'] = json.dumps(user_jwt)
    return redirect(settings.AUTHED_URL)

def google_refresh(request=None, user=None):
    if request:
        user = request.user
        if not user.is_authenticated:
            return JsonResponse({'status': ''}, status=401)
    elif user:
        user = user
    refresh_token = user.socialuser.refresh_token
    if refresh_token:
        client_secret = settings.GOO_CLIENT_SECRET
        client_id = settings.GOO_CLIENT_ID
        token_url = 'https://www.googleapis.com/oauth2/v4/token'
        response = requests.post(token_url, params={'grant_type': 'refresh_token'}, data={
            'client_id': client_id, 'client_secret': client_secret, 'refresh_token': refresh_token
        }).json()
        updating_token(user, token=response['access_token'])
        return JsonResponse({'status': 'refreshed'}, status=200)
    return JsonResponse({'status': ''}, status=404)
