django-rest-social-jwt-auth
---------------------------

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

2. Include the polls URLconf in your project urls.py like this::
```python
path('<path>/', include('django_rest_social_jwt_auth.urls'))
```

Paths are:

`facebook/`
`github/`
`google/`

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
