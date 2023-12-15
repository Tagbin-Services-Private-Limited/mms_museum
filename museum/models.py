from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from .storage import OverwriteStorage

# Create your models here.

class CommonInfo(models.Model):
    created_at=models.DateTimeField(editable=False)
    updated_at=models.DateTimeField(null=True,blank=True)
    created_by=models.ForeignKey(User,on_delete=models.CASCADE,null=True,blank=True,related_name='%(class)s_requests_created')
    updated_by=models.ForeignKey(User,on_delete=models.CASCADE,null=True,blank=True,related_name='%(class)s_requests_updated')

    def save(self, *args, **kwargs):
        if not self.id:
            self.created_at = timezone.now()
        self.updated_at = timezone.now()
        return super(CommonInfo, self).save(*args, **kwargs)

    class Meta:
        abstract=True
    

class Organization(CommonInfo):
    name = models.CharField(max_length=100)
    description = models.TextField(default='',blank=True)
    is_active = models.BooleanField(default=True)
    image = models.ImageField(upload_to ='organization_image/',null=True,blank=True)

    def __str__(self):
        return self.name


class Project(CommonInfo):
    name = models.CharField(max_length=100)
    description = models.TextField(default='',blank=True)
    is_active = models.BooleanField(default=True)
    image = models.ImageField(upload_to ='project_image/',null=True,blank=True)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,null=True)


    def __str__(self):
        return self.name

class Floor(CommonInfo):
    name = models.CharField(max_length=100)
    description = models.TextField(default='',blank=True)
    is_active = models.BooleanField(default=True)
    image = models.ImageField(upload_to ='floor_image/',null=True,blank=True)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,null=True)
    project=models.ForeignKey(Project,on_delete=models.CASCADE,null=True)
    

    def __str__(self):
        return self.name


class Zone(CommonInfo):
    name = models.CharField(max_length=100)
    description = models.TextField(default='',blank=True)
    is_active = models.BooleanField(default=True)
    image = models.ImageField(upload_to ='zone_image/',null=True,blank=True)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,null=True)
    project=models.ForeignKey(Project,on_delete=models.CASCADE,null=True)
    floor=models.ForeignKey(Floor,on_delete=models.CASCADE,null=True)
    

    def __str__(self):
        return self.name


class Exhibit(CommonInfo):
    name = models.CharField(max_length=100)
    description = models.TextField(default='',blank=True)
    is_active = models.BooleanField(default=True)
    image = models.ImageField(upload_to ='exhibit_image/',null=True,blank=True)
    project=models.ForeignKey(Project,on_delete=models.CASCADE,null=True)
    zone=models.ForeignKey(Zone,on_delete=models.CASCADE,null=True)
    is_exhibit_show = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class Tag(CommonInfo):
    name = models.CharField(max_length=25)
    description = models.CharField(max_length=255, default='',blank=True)
    is_active = models.BooleanField(default=True)
    image = models.ImageField(upload_to ='tag_image/',null=True,blank=True)
    project=models.ForeignKey(Project,on_delete=models.CASCADE,null=True)
    exhibit=models.ForeignKey(Exhibit,on_delete=models.CASCADE,null=True)

    def __str__(self):
        return self.name



class Attraction(CommonInfo):
    name = models.CharField(max_length=25)
    description = models.CharField(max_length=255, default='',blank=True)
    is_active = models.BooleanField(default=True)
    image = models.ImageField(upload_to ='attraction_image/',null=True,blank=True)
    project=models.ForeignKey(Project,on_delete=models.CASCADE,null=True)
    exhibit=models.ForeignKey(Exhibit,on_delete=models.CASCADE,null=True)
   

    def __str__(self):
        return self.name


class Node(CommonInfo):
    name = models.CharField(max_length=100,blank=True,null=True)
    node_name = models.CharField(max_length=100,blank=True,null=True)
    description = models.TextField(default='',blank=True,null=True)
    ip = models.CharField(max_length=100,blank=True,null=True)
    is_active = models.BooleanField(default=True)
    is_config = models.BooleanField(default=False)
    is_online = models.BooleanField(default=False)
    os_type = models.CharField(max_length=150, default='',blank=True,null=True)
    mac_addr = models.CharField(max_length=150, null=False, unique=True)
    port = models.CharField(max_length=50, default='',blank=True,null=True)
    unique_reg_code = models.CharField(max_length=400,blank=True,null=True)
    os_name = models.CharField(max_length=255, default='',blank=True,null=True)
    os_arch = models.CharField(max_length=255, default='',blank=True,null=True)
    total_disc_space = models.CharField(max_length=25, default='',blank=True,null=True)
    total_cpu = models.CharField(max_length=25, default='',blank=True,null=True)
    total_ram = models.CharField(max_length=25, default='',blank=True,null=True)
    # for storing latest node log
    disc_space_usage = models.IntegerField(default=0,null=True,blank=True) 
    cpu_usage = models.IntegerField(default=0,null=True,blank=True)
    ram_usage = models.IntegerField(default=0,null=True,blank=True)
    #end for storing latest node log
    temprature = models.CharField(max_length=25, default='',blank=True,null=True)
    content_metadata = models.TextField(default='',blank=True,null=True)
    version = models.CharField(max_length=25, default='',blank=True,null=True)#doubt
    # file field or textfield
    pem_file = models.TextField(default='',blank=True,null=True)
    heartbeat_rate = models.IntegerField(default=10)
    image = models.ImageField(upload_to ='node_image/',null=True,blank=True)
    project=models.ForeignKey(Project,on_delete=models.CASCADE,null=True,blank=True)
    floor=models.ForeignKey(Floor,on_delete=models.CASCADE,null=True,blank=True)
    zone=models.ForeignKey(Zone,on_delete=models.CASCADE,null=True,blank=True)
    exhibit=models.ForeignKey(Exhibit,on_delete=models.CASCADE,null=True,blank=True)
    user = models.ForeignKey(User, null=True, on_delete=models.CASCADE,blank=True)
    current_video_status = models.CharField(max_length=100, default='',blank=True,null=True)
    current_video_name = models.CharField(max_length=500, default='',blank=True,null=True)
    current_video_number = models.IntegerField(default=0,null=True,blank=True)
    current_timestamp = models.FloatField(default=0.0,null=True,blank=True)
    current_volume = models.IntegerField(default=0,null=True,blank=True)
    total_videos = models.IntegerField(default=0,null=True,blank=True)
    video_duration = models.FloatField(default=0.0,null=True,blank=True)
    video_list = models.TextField(default='',blank=True,null=True)
    sequence_id = models.IntegerField(default=0,null=True,blank=True)
    is_audio_guide = models.BooleanField(default=False)
    CATEGORY_CHOICES=[('NUC', 'NUC'),
                    ('SOC', 'SOC'),
                    ('WATCHOUT', 'WATCHOUT'),
                    ('SHOW', 'SHOW'),
                    ('INTERACTIVE', 'INTERACTIVE'),
		    ('PROJECTOR', 'PROJECTOR'),
		    ('PROJECTOR_B15', 'PROJECTOR_B15'),
                        ]
    category = models.CharField(max_length=100,null=True,blank=True,choices=CATEGORY_CHOICES)
    is_control_panel = models.BooleanField(default=True)
    uptime =models.FloatField(default=0.0,null=True,blank=True)
    encrypted_port = models.CharField(max_length=50, default='',blank=True,null=True)
    def __str__(self):
        if self.id is not None:
            return f"{self.name}-{self.id}"
        else:
            return self.name


        
class NodeLog(CommonInfo):
    disc_space_usage = models.IntegerField(default=0,null=True,blank=True) 
    cpu_usage = models.IntegerField(default=0,null=True,blank=True)
    ram_usage = models.IntegerField(default=0,null=True,blank=True)
    temparature = models.FloatField(default=0.0,null=True,blank=True)
    node = models.ForeignKey(Node, on_delete=models.CASCADE,null=True)
    uptime =models.FloatField(default=0.0,null=True,blank=True)
    version = models.CharField(max_length=25, default='',blank=True,null=True)
   


    def __str__(self):
        return self.node.mac_addr


class Command(CommonInfo):
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    project=models.ForeignKey(Project,on_delete=models.CASCADE,null=True)



    def __str__(self):
        return self.name


class MMSUser(CommonInfo):
    user = models.ForeignKey(User, null=True, on_delete=models.CASCADE,blank=True)
    is_active = models.BooleanField(default=True)
    organization=models.ForeignKey(Organization,on_delete=models.CASCADE,null=True)
    zone = models.ManyToManyField(Zone)
    enable_dashboard = models.BooleanField(default=False)
    enable_devices = models.BooleanField(default=False)
    enable_command_logs = models.BooleanField(default=False)
    enable_show = models.BooleanField(default=False)
    enable_content_upload = models.BooleanField(default=False)
    enable_control_panel = models.BooleanField(default=False)
    enable_software_update = models.BooleanField(default=False)
    enable_museum_on_off = models.BooleanField(default=False)
    enable_reports = models.BooleanField(default=False)
    enable_moderation1 = models.BooleanField(default=False)
    enable_moderation2 = models.BooleanField(default=False)
    enable_analytics = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username


def node_file_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/user_<id>/<filename>
    mac_addr = instance.node.mac_addr.replace(":", "_")
    return '{0}/{1}'.format("content/"+mac_addr,filename)

def node_software_path(instance, filename):
    # file will be uploaded to MEDIA_ROOT/user_<id>/<filename>
    mac_addr = instance.node.mac_addr.replace(":", "_")
    return '{0}/{1}'.format("software/"+mac_addr,filename)


class NodeFile(CommonInfo):
    node=models.ForeignKey(Node,on_delete=models.CASCADE,null=True)
    node_file=models.FileField(upload_to=node_file_path,null=True,blank=True,storage=OverwriteStorage())
    position = models.IntegerField(default=0,null=True,blank=True)

    def __str__(self):
        return str(self.node.id)



class CommandLog(CommonInfo):
    node=models.ForeignKey(Node,on_delete=models.CASCADE,null=True)
    command=models.ForeignKey(Command,on_delete=models.CASCADE,null=True)


    def __str__(self):
        return self.command.name + '->' +self.node.name


class CommandLogBatch(CommonInfo):
    command_log=models.ForeignKey(CommandLog,on_delete=models.CASCADE,null=True)
    STATUS_CHOICES=[('FAILED', 'FAILED'),
                    ('SUCCESS', 'SUCCESS'),
                    ('ACKNOWLEDGED', 'ACKNOWLEDGED')
                        ]
    status = models.CharField(max_length=100,null=True,blank=True,choices=STATUS_CHOICES)
    message = models.TextField(default='',blank=True, null=True)



    def __str__(self):
        return self.status

class NodeSoftware(CommonInfo):
    node=models.ForeignKey(Node,on_delete=models.CASCADE,null=True)
    node_software=models.FileField(upload_to=node_software_path,null=True,blank=True, storage=OverwriteStorage())

    def __str__(self):
        return str(self.node.id)




class Show(CommonInfo):
    name = models.CharField(max_length=500,null=True,blank=True)
    description = models.TextField(default='',blank=True, null=True)
    is_active = models.BooleanField(default=True)
    show_status=models.BooleanField(default=False)
    start_time=models.DateTimeField(null=True,blank=True)
    
    

    def __str__(self):
        return str(self.name)


class ShowDetail(CommonInfo):
    node=models.ForeignKey(Node,on_delete=models.CASCADE,null=True,blank=True)
    show=models.ForeignKey(Show,on_delete=models.CASCADE,null=True)
    is_active = models.BooleanField(default=True)
    command=models.ForeignKey(Command,on_delete=models.CASCADE,null=True,blank=True,related_name='%(class)s_command_node')
    PROTOCOL_CHOICES=[('TCP', 'TCP'),
                    ('HTTP', 'HTTP'),
                    ('Serail', 'Serail'),
                    ('DMX', 'DMX')
                        ]
    protocol = models.CharField(max_length=100,null=True,blank=True,choices=PROTOCOL_CHOICES)
    payload = models.CharField(max_length=500,null=True,blank=True)
    protocol_byepass = models.CharField(max_length=100,null=True,blank=True,choices=PROTOCOL_CHOICES)
    payload_byepass = models.CharField(max_length=500,null=True,blank=True)
    command_byepass=models.ForeignKey(Command,on_delete=models.CASCADE,null=True,blank=True,related_name='%(class)s_command_byepass')
    start_time=models.IntegerField(default=0,null=True,blank=True)

    def __str__(self):
        return str(self.show.name)

class Moderation(CommonInfo):
    node=models.ForeignKey(Node,on_delete=models.CASCADE,null=True,blank=True)
    name = models.ImageField(upload_to='person_name/',null=True,blank=True)
    message = models.ImageField(upload_to='person_message/',null=True,blank=True)
    person_image=models.ImageField(upload_to='person_image/',null=True,blank=True)
    broadcast = models.BooleanField(default=False)
    vision_image=models.ImageField(upload_to='vision_image/',null=True,blank=True)
    pledge_image=models.ImageField(upload_to='pledge_image/',null=True,blank=True)
    title = models.CharField(max_length=1000,null=True,blank=True)

    

    def __str__(self):
        return str(self.name)


class ModerationStatus(CommonInfo):
    is_moderate = models.BooleanField(default=True)
    

    def __str__(self):
        return str(self.id)

class ExhibitShow(CommonInfo):
    exhibit=models.ForeignKey(Exhibit,on_delete=models.CASCADE,null=True,blank=True)
    total_seats = models.IntegerField(default=0,null=True,blank=True)
    occupied_seats = models.IntegerField(default=0,null=True,blank=True)
    timing = models.CharField(max_length=250,null=True,blank=True)
    
    

    def __str__(self):
        return str(self.exhibit.name)

class ExhibitShowBooking(CommonInfo):
    exhibit_show=models.ForeignKey(ExhibitShow,on_delete=models.CASCADE,null=True,blank=True)
    user = models.ForeignKey(User, null=True, on_delete=models.CASCADE,blank=True)
    number_of_seats = models.IntegerField(default=0,null=True,blank=True)
    status = models.BooleanField(default=False)
    
    
    

    def __str__(self):
        return str(self.exhibit_show.exhibit.name)   

class WatchoutVideo(CommonInfo):
    node=models.ForeignKey(Node,on_delete=models.CASCADE,null=True,blank=True)
    video_name = models.CharField(max_length=500, default='',blank=True,null=True)
    video_duration = models.FloatField(default=0.0,null=True,blank=True)
    video_position = models.IntegerField(default=0,null=True,blank=True)
    

    def __str__(self):
        return str(self.video_name)


class Holiday(CommonInfo):
    holiday = models.DateField()
    
    

    def __str__(self):
        return str(self.holiday)

class Report(CommonInfo):
    node=models.ForeignKey(Node,on_delete=models.CASCADE)
    online_percentage=models.IntegerField(default=0)
    report_date = models.DateField()
    downtime=models.FloatField(default=0.0)
    
    def __str__(self):
        #return self.node.name
        return self.node.name + "-->" +str(self.report_date) + "-->" + str(self.online_percentage) 

class ReportFailure(CommonInfo):
    reason = models.TextField(default='')
    reason_date = models.DateField()
    start_time=models.TimeField()
    end_time=models.TimeField()
    node = models.ManyToManyField(Node)
    
    def __str__(self):
        #return self.node.name
        return str(self.reason_date) + "-->" + str(self.reason) 



class PMSelection(CommonInfo):
    pm_name = models.CharField(max_length=500, default='')
    #category value will be 1 for selfie with pm and 2 for walk with pm.
    category=models.IntegerField(default=0)
    
    def __str__(self):
        #return self.node.name
        return self.pm_name
    
# class Language(CommonInfo):
#     language = models.CharField(max_length=100,null=True,blank=True)
#     node=models.ForeignKey(Node,on_delete=models.CASCADE,null=True)
#     command=models.ForeignKey(Command,on_delete=models.CASCADE,null=True)
#     message = models.TextField(default='',blank=True, null=True)



#     def __str__(self):
#         return self.status


# class CommandLog(CommonInfo):
#     STATUS_CHOICES=[('FAILED', 'FAILED'),
#                     ('SUCCESS', 'SUCCESS'),
#                     ('ACKNOWLEDGED', 'ACKNOWLEDGED')
#                         ]
#     status = models.CharField(max_length=100,null=True,blank=True,choices=STATUS_CHOICES)
#     node=models.ForeignKey(Node,on_delete=models.CASCADE,null=True)
#     command=models.ForeignKey(Command,on_delete=models.CASCADE,null=True)
#     message = models.TextField(default='',blank=True, null=True)



#     def __str__(self):
#         return self.status


# class CommandLog(CommonInfo):
#     STATUS_CHOICES=[('FAILED', 'FAILED'),
#                     ('SUCCESS', 'SUCCESS'),
#                     ('ACKNOWLEDGED', 'ACKNOWLEDGED')
#                         ]
#     status = models.CharField(max_length=100,null=True,blank=True,choices=STATUS_CHOICES)
#     node=models.ForeignKey(Node,on_delete=models.CASCADE,null=True)
#     command=models.ForeignKey(Command,on_delete=models.CASCADE,null=True)
#     message = models.TextField(default='',blank=True, null=True)



#     def __str__(self):
#         return self.status


# class CommandLog(CommonInfo):
#     STATUS_CHOICES=[('FAILED', 'FAILED'),
#                     ('SUCCESS', 'SUCCESS'),
#                     ('ACKNOWLEDGED', 'ACKNOWLEDGED')
#                         ]
#     status = models.CharField(max_length=100,null=True,blank=True,choices=STATUS_CHOICES)
#     node=models.ForeignKey(Node,on_delete=models.CASCADE,null=True)
#     command=models.ForeignKey(Command,on_delete=models.CASCADE,null=True)
#     message = models.TextField(default='',blank=True, null=True)



#     def __str__(self):
#         return self.status
