from setuptools import setup

setup(
    name='django-rest-social-jwt-auth',
    install_requires=[
        'Django>=2.0',
        'psycopg2_binary>=2.8.6',
        'PyJWT>=2.0',
        'requests-oauthlib>=1.3.0',
        'django-annoying>=0.10.6'
    ]
)
