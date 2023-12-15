from django.core.exceptions import PermissionDenied
from .models import MMSUser
from django.urls import resolve


def module_is_entry_mms_user(function):
    def wrap(request,*args, **kwargs): 
        mms_userO=MMSUser.objects.get(user=request.user)
        if resolve(request.path_info).url_name=="dashboard":
            if mms_userO.enable_dashboard == True:
                return function(request, *args, **kwargs)
            else:
                raise PermissionDenied
        elif resolve(request.path_info).url_name=="devices" or resolve(request.path_info).url_name=="devices_v2":
            if mms_userO.enable_devices == True:
                return function(request, *args, **kwargs)
            else:
                raise PermissionDenied
        elif resolve(request.path_info).url_name=="control_panel" or resolve(request.path_info).url_name=="control_panel_v2":
            if mms_userO.enable_control_panel == True:
                return function(request, *args, **kwargs)
            else:
                raise PermissionDenied
        elif resolve(request.path_info).url_name=="content_upload" or resolve(request.path_info).url_name=="content_upload_v2":
            # print(f"Request: {request}, MMSUser: {mms_userO}, Args: {args}, Kwargs: {kwargs}")
            if mms_userO.enable_content_upload == True:
                return function(request, *args, **kwargs)
            else:
                raise PermissionDenied
        elif resolve(request.path_info).url_name=="command_logs":
            if mms_userO.enable_command_logs == True:
                return function(request, *args, **kwargs)
            else:
                raise PermissionDenied
        elif resolve(request.path_info).url_name=="reports":
            if mms_userO.enable_reports == True:
                return function(request, *args, **kwargs)
            else:
                raise PermissionDenied
        elif resolve(request.path_info).url_name=="analytics":
            if mms_userO.enable_analytics == True:
                return function(request, *args, **kwargs)
            else:
                raise PermissionDenied
        elif resolve(request.path_info).url_name=="software_update" or resolve(request.path_info).url_name=="software_update_v2":
            if mms_userO.enable_software_update == True:
                return function(request, *args, **kwargs)
            else:
                raise PermissionDenied
        elif resolve(request.path_info).url_name=="show":
            if mms_userO.enable_show == True:
                return function(request, *args, **kwargs)
            else:
                raise PermissionDenied
        elif resolve(request.path_info).url_name=="show_on_ui":
            if mms_userO.enable_moderation1 == True:
                return function(request, *args, **kwargs)
            else:
                raise PermissionDenied
        elif resolve(request.path_info).url_name=="delete_from_ui":
            if mms_userO.enable_moderation2 == True:
                return function(request, *args, **kwargs)
            else:
                raise PermissionDenied
        elif resolve(request.path_info).url_name=="museum_on_off":
            if mms_userO.enable_museum_on_off == True:
                return function(request, *args, **kwargs)
            else:
                raise PermissionDenied
        else:
            return function(request, *args, **kwargs)
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap