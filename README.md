django-rest-social-jwt-auth
---------------------------
***
1. Add app to your INSTALLED_APPS setting like this::
```python
INSTALLED_APPS = [
    ...
    'django_rest_social_jwt_auth',
    'annoying'  # also needed

]
```
Make migration for app
```python
python manage.py makemigrations django_rest_social_jwt_auth
```
***
2. Include the polls URLconf in your project urls.py like this::
```python
path('<path>/', include('django_rest_social_jwt_auth.urls'))
```

Paths are:

    General:
        social_logout/
        
    Facebook:
        facebook/

    Google:
        google/
        google_refresh/

    GitHub:
        github/
        github_refresh/

***
3. In settings.py:

*For JWT*
```python
JWT_SECRET = 'super-secret-key'
JWT_ALGORITHM = 'HS256'
JWT_ROLE = DATABASES['default']['USER']
JWT_EXP = <amount in minutes>
```

*For database*
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': '...',
        'USER': '...',
        'PASSWORD': '...',
        'HOST': '...',
        'PORT': '...',
    }
}
```

*For social*
```python
FB_CLIENT_ID = '...'
FB_CLIENT_SECRET = '...'

GH_CLIENT_ID = '...'
GH_CLIENT_SECRET = '...'

GOO_CLIENT_ID = '...'
GOO_CLIENT_SECRET = '...'
```

*For redirects*
```python
AUTHED_URL = '<your view name after LogIn>'
LOGOUT_URL = '<your view name after LogOut>'
```
***
4. Features

    Model
   
        SocialUser - is o2o to your User model.
            social_organisation - name of provider
            social_id - user id in provider db
            token - access token from provider
            refresh_token - refresh token from provider

    Views

        App provide few usefull methods:

            is_auth_social(request) - return provider name or False. None - in case unauthorized user
            social_logout(request) - logout user as usuall + remove 'jwt' from session and remove provider's 'token' from db
            get_token(request=None, user=None) - return JsonResponse with field 'token' and status
            get_refresh_token(request=None, user=None) - return JsonResponse with field 'refresh_token' and status
                *if 'status' is 404, it does not mean that smth wrong, due to some providers or apps config could not have expiration date for token*
***

5. Flow


    LogIn

    First (or not first) user try to enter the system using any social net, next will happen:
    1) He will be redirected to choosen provider's LogIn page (or not, if user have session with him).
    2) After he enters, he will be redirected to callback func.
        2.1) Callback func will retrieve users data from provider (e.g. token, refr, id, name etc.)
        2.2) Func will try to find among SocialUser table user, using it's 'social_id' and 'social_organisation'
            2.2.1 -) In case if no SocialUser will be found, the func will create one (and your User, in the usual django user manner), and return User
            2.2.1 +) In case of finding - just refresh it's token (and refresh token), and also return User
        2.3) After user will be returned, JWT will be created.
        2.4) The user will be LogIn, using common login(), and created JWT will be is request.session['jwt']
        2.5) User will be redirected using redirect() with settings.AUTHED_URL param.
   
|

    LogOut

    When LoggedIn user try to LogOut, using `social_logout/` url, next will happen:
    Whether authenticated user or not he will be redirected using redirect(), with settings.LOGOUT_URL param,
    but if user is authenticated - he will be logged out using common logout() func, 'jwt' will be removed
    from request.session, and the token field will become empty (but not refresh token field).

|

    Refreshing

    When you try to refresh, the next will happen:
    First of all, you can refresh token either using request or user instance.
        -- If request - user must be authenticated, otherwise - 401, and empty JsonResponse 'status' field.
    Next, will be try to get refresh token from db. If succeed - 'status' will be 'refreshed'. If failed - status 404
        *Here is the same situation as with get_refresh_token method above*
    
        