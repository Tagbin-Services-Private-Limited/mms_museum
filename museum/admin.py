from django.contrib import admin
from .models import *
from import_export.admin import ImportExportModelAdmin

# Register your models here.
@admin.register(Organization)
class OrganizationAdmin(ImportExportModelAdmin):
    pass

@admin.register(Project)
class ProjectAdmin(ImportExportModelAdmin):
    pass

@admin.register(Floor)
class FloorAdmin(ImportExportModelAdmin):
    pass

@admin.register(Zone)
class ZoneAdmin(ImportExportModelAdmin):
    pass

@admin.register(Exhibit)
class ExhibitAdmin(ImportExportModelAdmin):
    pass

@admin.register(Node)
class NodeAdmin(ImportExportModelAdmin):
    pass

@admin.register(NodeLog)
class NodeLogAdmin(ImportExportModelAdmin):
    pass

@admin.register(Command)
class CommandAdmin(ImportExportModelAdmin):
    pass

@admin.register(MMSUser)
class MMSUserAdmin(ImportExportModelAdmin):
    pass

@admin.register(NodeFile)
class NodeFileAdmin(ImportExportModelAdmin):
    pass

@admin.register(CommandLog)
class CommandLogAdmin(ImportExportModelAdmin):
    pass

@admin.register(NodeSoftware)
class NodeSoftwareAdmin(ImportExportModelAdmin):
    pass

@admin.register(Show)
class ShowAdmin(ImportExportModelAdmin):
    pass

@admin.register(ShowDetail)
class ShowDetailAdmin(ImportExportModelAdmin):
    pass

@admin.register(CommandLogBatch)
class CommandLogBatchAdmin(ImportExportModelAdmin):
    pass

@admin.register(Moderation)
class ModerationAdmin(ImportExportModelAdmin):
    pass

@admin.register(ModerationStatus)
class ModerationStatusAdmin(ImportExportModelAdmin):
    pass

@admin.register(ExhibitShow)
class ExhibitShowAdmin(ImportExportModelAdmin):
    pass

@admin.register(ExhibitShowBooking)
class ExhibitShowBookingAdmin(ImportExportModelAdmin):
    pass

@admin.register(WatchoutVideo)
class WatchoutVideoAdmin(ImportExportModelAdmin):
    pass

@admin.register(Holiday)
class HolidayAdmin(ImportExportModelAdmin):
    pass


@admin.register(Report)
class ReportAdmin(ImportExportModelAdmin):
    pass

@admin.register(ReportFailure)
class ReportFailureAdmin(ImportExportModelAdmin):
    pass

@admin.register(PMSelection)
class PMSelectionAdmin(ImportExportModelAdmin):
    pass

#@admin.register(User)
#class UserAdmin(ImportExportModelAdmin):
 #   pass



#admin.site.register(Organization)
#admin.site.register(Project)
#admin.site.register(Floor)
#admin.site.register(Zone)
#admin.site.register(Exhibit)
#admin.site.register(Node)
#admin.site.register(NodeLog)
#admin.site.register(Command)
#admin.site.register(MMSUser)
#admin.site.register(NodeFile)
#admin.site.register(CommandLog)
#admin.site.register(NodeSoftware)
#admin.site.register(Show)
#admin.site.register(ShowDetail)
#admin.site.register(CommandLogBatch)
#admin.site.register(Moderation)
#admin.site.register(ModerationStatus)
#admin.site.register(ExhibitShow)
#admin.site.register(ExhibitShowBooking)
#admin.site.register(WatchoutVideo)
admin.site.site_header='MMS ADMIN'

