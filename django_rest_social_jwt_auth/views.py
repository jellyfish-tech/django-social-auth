from django.conf import settings
from django.http.response import JsonResponse
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from django.urls import resolve, reverse
from django.contrib.auth.hashers import make_password
from requests_oauthlib import OAuth2Session
from requests_oauthlib.compliance_fixes import facebook_compliance_fix
from http import HTTPStatus
from .models import SocialUser
from datetime import datetime, timedelta
import json
import jwt


def create_jwt(user):
    token = jwt.encode({
        'role': settings.JWT_ROLE,
        'userid': str(user.id),
        'exp': (datetime.now() + timedelta(minutes=settings.JWT_EXP)).timestamp(),
    }, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return {'token': token}

# Not uses
def prepare_response(status: int, token=None, error=None, message=None):
    resp = {'status': status}
    if error:
        resp['data'] = {'error': {'message': error}}
    elif token:
        if isinstance(token, dict):
            resp['data'] = token
        elif isinstance(token, str):
            resp['data'] = {'token': token}
    elif message:
        resp['data'] = {'message': message}
    resp['data']['status'] = status
    return resp

def user_busines(social_data: dict, social_organisation):
    social_user_id = social_data.get('id')
    social_user = SocialUser.objects.filter(social_id=social_user_id, social_organisation=social_organisation).first()
    if not social_user:
        social_user_name = social_data.get('name') or social_data.get('login')
        social_user_password = make_password(password=None)
        social_user = get_user_model().objects.create(username=social_user_name, password=social_user_password)
        social_user.socialuser = SocialUser(user=social_user, social_organisation=social_organisation,
                                        social_id=social_user_id)
        social_user.socialuser.save()
    else:
        social_user = get_user_model().objects.get(id=social_user.user_id)
    return social_user


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

    user = user_busines(response, 'facebook')
    user_jwt = create_jwt(user)
    # TODO add redirect mechanism to developer's page || probably through settings and resolve method
    return JsonResponse(user_jwt)



def signin_github(request):
    base_url = 'https://github.com/login/oauth/authorize'
    redirect_uri = request.build_absolute_uri(reverse(gh_callback))
    client_id = settings.GH_CLIENT_ID

    gh = OAuth2Session(client_id, redirect_uri=redirect_uri)

    authorization_url, state = gh.authorization_url(base_url)
    return redirect(authorization_url)

def gh_callback(request):
    token_url = 'https://github.com/login/oauth/access_token'
    redirect_uri = request.build_absolute_uri(reverse(gh_callback))

    client_secret = settings.GH_CLIENT_SECRET
    client_id = settings.GH_CLIENT_ID

    gh = OAuth2Session(client_id, redirect_uri=redirect_uri)
    token = gh.fetch_token(token_url, client_secret=client_secret, authorization_response=request.build_absolute_uri())
    response = gh.get('https://api.github.com/user').json()
    user = user_busines(response, 'github')
    user_jwt = create_jwt(user)
    # TODO add redirect mechanism to developer's page || probably through settings and resolve method
    return JsonResponse(user_jwt)



def signin_google(request):
    base_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    redirect_uri = request.build_absolute_uri(reverse(goo_callback))
    client_id = settings.GOO_CLIENT_ID
    scope = [
        # "https://www.googleapis.com/auth/userinfo.email",
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
    user = user_busines(response, 'google')
    user_jwt = create_jwt(user)
    # TODO add redirect mechanism to developer's page || probably through settings and resolve method
    return JsonResponse(user_jwt)
