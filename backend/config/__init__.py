try:
    # Use PyMySQL (pure Python) as a drop-in stand-in for MySQLdb so the
    # project runs without a C compiler / MySQL client headers - this is
    # what makes Windows setup painless. Must run before anything imports
    # django.db (hence: here, in the package __init__, before settings
    # or celery are touched).
    import pymysql
    pymysql.install_as_MySQLdb()
except ImportError:
    # mysqlclient installed instead (e.g. on a production Linux box) -
    # nothing to do.
    pass

from .celery import app as celery_app

__all__ = ("celery_app",)
