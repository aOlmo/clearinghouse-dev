import os
import sys

deployment_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
repy_runtime_path = os.path.join(deployment_path, "seattle")

sys.path.insert(0, repy_runtime_path)
sys.path.insert(0, deployment_path)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "clearinghouse.website.settings")

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()

