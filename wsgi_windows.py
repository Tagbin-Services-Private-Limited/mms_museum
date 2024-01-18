import os
import sys
sys.path.append('C:/Users/tagbi/Desktop/TAGBIN_CODE/')

from django.core.wsgi import get_wsgi_application

# Set the DJANGO_SETTINGS_MODULE environment variable to point to your project's settings module.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mms.settings')

# Create a WSGI application using Django's get_wsgi_application function.
application = get_wsgi_application()
