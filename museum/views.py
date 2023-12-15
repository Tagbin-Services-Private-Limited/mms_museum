import numbers
from django.shortcuts import render, redirect
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import *
from .serializers import *
from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from rest_framework.authtoken.models import Token
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from .tcp_client import TCPClient
from .tcp_client import EncryptedTCPClient
import os
from django.db.models import Q, Sum, Avg
from django.utils import timezone
import time
from django.core.paginator import Paginator
# import base64
# import io
# from PIL import Image
import base64
from django.core.files.base import ContentFile
import json
from django.contrib.auth import logout
from django.contrib.auth.decorators import user_passes_test
from wakeonlan import send_magic_packet
import requests
import datetime
from datetime import timedelta
from django.utils.timezone import make_aware
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from django.contrib.auth.hashers import check_password
from django.contrib.auth import update_session_auth_hash
from .decorators import module_is_entry_mms_user



#Function for tcp encryption
def encrypt(message, pub_key):
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)
# Create your views here.

# @api_view(['POST'])
# def node_registration(request):

#     if request.method == 'POST':
#         if Node.objects.filter(mac_addr=request.data['mac_addr']).exists():
#             nodeO=Node.objects.get(mac_addr=request.data['mac_addr'])
#             if nodeO.is_config==True:
#                 return Response({"success" : nodeO.name, "auth_token" : nodeO.auth_token})
#             else:
#                 return Response({'success' : {'status' : "REG_INIT"}, "message": "Device already added but not configured.", "error": "false" })

#         else:
#             serializer = NodeSerializer(data=request.data)
#             if serializer.is_valid():
#                 serializer.save()
#                 return Response({'success' : {'status' : "REG_INIT"}, "message": "Device Added Successfully.", "error": "false" }, status=status.HTTP_201_CREATED)
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class device_status_api(APIView):
	#permission_classes = (IsAuthenticated,)
	def get(self, request):
		data=[]
		kwargs={}
		#mms_userO=MMSUser.objects.get(user=request.user)
		kwargs['{0}'.format('is_config')]= True
		kwargs['{0}'.format('is_control_panel')]= True
		#kwargs['{0}__{1}'.format('zone','in')]= mms_userO.zone.all()

		if 'floor_id[]' in request.GET:
			floor_id=request.GET.getlist('floor_id[]')
			kwargs['{0}__{1}__{2}'.format('floor', 'pk', 'in')]= floor_id

		if 'zone_id[]' in request.GET:
			zone_id=request.GET.getlist('zone_id[]')
			kwargs['{0}__{1}__{2}'.format('zone', 'pk', 'in')]= zone_id

		if 'exhibit_id[]' in request.GET:
			exhibit_id=request.GET.getlist('exhibit_id[]')
			kwargs['{0}__{1}__{2}'.format('exhibit', 'pk', 'in')]= exhibit_id
		
		if 'status' in request.GET:
			status=request.GET.get('status')
			if status == 'online':
				kwargs['{0}__{1}'.format('updated_at','gt')]=timezone.now()-timezone.timedelta(seconds=131)
			elif status=="offline":
				kwargs['{0}__{1}'.format('updated_at','lt')]=timezone.now()-timezone.timedelta(seconds=131)

		if 'name' in request.GET:
			name=request.GET.get('name')
			kwargs['{0}__{1}'.format('name', 'icontains')]=name
		
		nodeO=Node.objects.filter(**kwargs).order_by('sequence_id')

		

		for i in nodeO:
			if i.video_list:
				data.append({'id' : i.pk, 'name' : i.name, 'ip' : i.ip, 'floor' : i.floor.name, 'zone' : i.zone.name, 'exhibit' : i.exhibit.name,'status' : device_status_check(i.pk), 'unique_reg_code' : i.unique_reg_code, 'mac_addr' : i.mac_addr, 'updated_at' : i.updated_at, 'version' : i.version, 'current_video_status' : i.current_video_status, 'current_video_name' : i.current_video_name, 'current_video_number' : i.current_video_number, 'current_timestamp' : i.current_timestamp,'current_volume' : i.current_volume, "total_videos" : i.total_videos, 'video_duration' : i.video_duration, 'video_list' : eval(i.video_list)})
			else:
				data.append({'id' : i.pk, 'name' : i.name, 'ip' : i.ip, 'floor' : i.floor.name, 'zone' : i.zone.name, 'exhibit' : i.exhibit.name,'status' : device_status_check(i.pk), 'unique_reg_code' : i.unique_reg_code, 'mac_addr' : i.mac_addr, 'updated_at' : i.updated_at, 'version' : i.version, 'current_video_status' : i.current_video_status, 'current_video_name' : i.current_video_name, 'current_video_number' : i.current_video_number, 'current_timestamp' : i.current_timestamp,'current_volume' : i.current_volume, "total_videos" : i.total_videos, 'video_duration' : i.video_duration, 'video_list' : i.video_list})

				

			#return JsonResponse({'data': data, 'command' : command_list})

		return Response({"data": data},status=HTTP_200_OK)

class node_registration(APIView):
	@csrf_exempt

	def post(self, request):
		print(request.data)
		name=request.data.get("name")
		node_name=request.data.get("node_name")
		description=request.data.get("description")
		ip=request.data.get("ip")
		os_type=request.data.get("os_type")
		mac_addr=request.data.get("mac_addr")
		port=request.data.get("port")
		unique_reg_code=request.data.get("unique_reg_code")
		os_name=request.data.get("os_name")
		os_arch=request.data.get("os_arch")
		total_disc_space=request.data.get("total_disc_space")
		total_cpu=request.data.get("total_cpu")
		total_ram=request.data.get("total_ram")
		temprature=request.data.get("temprature")
		content_metadata=request.data.get("content_metadata")
		version=request.data.get("version")
		pem_file=request.data.get("pem_file")
		encrypted_port=request.data.get("encrypted_port")
		if mac_addr!=""  and mac_addr!=None:
			if User.objects.filter(username=mac_addr).exists() and Node.objects.filter(mac_addr=mac_addr).exists():
				print('--------------------inside iffffffffffffffffff')
				user=User.objects.get(username=mac_addr)
				print('--------------------inside iffffffffffffffffff2')
				nodeO=Node.objects.get(mac_addr=mac_addr)
				print('--------------------inside iffffffffffffffffff3',user,nodeO)
				if nodeO.is_config==True:
					token, _ = Token.objects.get_or_create(user=user)
					if nodeO.pem_file:
						pass
					else:
						nodeO.pem_file=pem_file
						nodeO.save()
					if nodeO.encrypted_port:
						pass
					else:
						nodeO.encrypted_port=encrypted_port
						nodeO.save()
					return Response({"success": {'mac_addr' : nodeO.mac_addr, 'auth_token' : token.key, 'status' : 'REG_APPROVED', 'heartbeat_rate' : nodeO.heartbeat_rate}, 'error' : False },status=HTTP_200_OK)
				else:
					return Response({'success' : {'status' : "REG_INIT"}, "message": "Device already added but not configured.", "error": False },status=HTTP_200_OK)
			else:
				print('--------------------inside elseeeeeeeeeeeeeeeeee')
				user=User.objects.create_user(username=mac_addr,password=mac_addr)
				user.save()
				nodeO=Node.objects.create(mac_addr=mac_addr)
				nodeO.name=name
				nodeO.node_name=node_name
				nodeO.description=description
				nodeO.ip=ip
				nodeO.os_type=os_type
				nodeO.port=port
				nodeO.unique_reg_code=unique_reg_code
				nodeO.os_name=os_name
				nodeO.os_arch=os_arch
				nodeO.total_disc_space=total_disc_space
				nodeO.total_cpu=total_cpu
				nodeO.total_ram=total_ram
				nodeO.temprature=temprature
				nodeO.content_metadata=content_metadata
				nodeO.version=version
				nodeO.pem_file=pem_file
				nodeO.user=user
				print("---------------------node o valje",nodeO)
				projectO=Project.objects.get(name="Testing museum")
				nodeO.project=projectO
				nodeO.encrypted_port=encrypted_port
				print("---------------------node o valje",nodeO)
				nodeO.save()

				return Response({'success' : {'status' : "REG_INIT"}, "message": "Device Added Successfully.", "error": False }, status=HTTP_200_OK)
		else:
			return Response({"message": "Mac Address is required for Node Registration.", "error": True },status=HTTP_200_OK)



class node_log(APIView):
	permission_classes = (IsAuthenticated,)
	@csrf_exempt
	def post(self, request):
		try:
			nodeO=Node.objects.get(user=request.user)
			# this if is for ignoring heartbeats after 10 seconds and accepting after 2 minutes.
			if NodeLog.objects.filter(node=nodeO).exists():
				latestO=NodeLog.objects.filter(node=nodeO).order_by('-id')[0]
				print(timezone.now()- latestO.updated_at)
				if (timezone.now()- latestO.updated_at < timezone.timedelta(seconds=119)) and "command_log_id" not in request.data:
					print("Rejected")
					return Response({"message": "Heartbeat added Successfully"},status=HTTP_200_OK)
				else:
					print("Accepted")
					node_logO=NodeLog.objects.create(node=nodeO)
					if "temparature" in request.data:
						temparature=request.data.get("temparature")
						node_logO.temparature=temparature
					if "uptime" in request.data:
						uptime=request.data.get("uptime")
						nodeO.uptime=uptime
						node_logO.uptime=uptime
					if "version" in request.data:
						version=request.data.get("version")
						nodeO.version=version
						node_logO.version=version
					if "disc_space_usage" in request.data:
						disc_space_usage=request.data.get("disc_space_usage")
						nodeO.disc_space_usage=disc_space_usage
						node_logO.disc_space_usage=disc_space_usage
					if "cpu_usage" in request.data:
						cpu_usage=request.data.get("cpu_usage")
						nodeO.cpu_usage=cpu_usage
						node_logO.cpu_usage=cpu_usage
					if "ram_usage" in request.data:
						ram_usage=request.data.get("ram_usage")
						nodeO.ram_usage=ram_usage
						node_logO.ram_usage=ram_usage
					if "current_video_status" in request.data:
						current_video_status=request.data.get("current_video_status")
						nodeO.current_video_status=current_video_status
					if "current_video_name" in request.data:
						current_video_name=request.data.get("current_video_name")
						nodeO.current_video_name=current_video_name
					if "current_video_number" in request.data:
						current_video_number=request.data.get("current_video_number")
						nodeO.current_video_number=current_video_number
					if "current_timestamp" in request.data:
						current_timestamp=request.data.get("current_timestamp")
						nodeO.current_timestamp=current_timestamp
					if "current_volume" in request.data:
						current_volume=request.data.get("current_volume")
						nodeO.current_volume=current_volume
					if "totalVideos" in request.data:
						total_videos=request.data.get("totalVideos")
						nodeO.total_videos=total_videos
					if "vduration" in request.data:
						video_duration=request.data.get("vduration")
						nodeO.video_duration=video_duration
					if "video_list" in request.data:
						video_list=request.data.get("video_list")
						nodeO.video_list=video_list
					nodeO.save()
					node_logO.save()
					if "command_log_id" in request.data:
						command_log_id=request.data.get("command_log_id")
						command_status=request.data.get("command_status")
						command_message=request.data.get("command_message")
						command_logO=CommandLog.objects.get(pk=command_log_id)
						# command_logO.status=command_status
						# command_logO.message=command_message
						# command_logO.updated_by=request.user
						# command_logO.save()
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status=command_status
						command_log_batchO.message=command_message
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						return Response({"message": "Heartbeat added Successfully and Command logs updated successfully."},status=HTTP_200_OK)
					else:
						return Response({"message": "Heartbeat added Successfully"},status=HTTP_200_OK)
			else:
				node_logO=NodeLog.objects.create(node=nodeO)
				if "temparature" in request.data:
					temparature=request.data.get("temparature")
					node_logO.temparature=temparature
				if "uptime" in request.data:
					uptime=request.data.get("uptime")
					nodeO.uptime=uptime
					node_logO.uptime=uptime
				if "version" in request.data:
					version=request.data.get("version")
					nodeO.version=version
					node_logO.version=version
				if "disc_space_usage" in request.data:
					disc_space_usage=request.data.get("disc_space_usage")
					nodeO.disc_space_usage=disc_space_usage
					node_logO.disc_space_usage=disc_space_usage
				if "cpu_usage" in request.data:
					cpu_usage=request.data.get("cpu_usage")
					nodeO.cpu_usage=cpu_usage
					node_logO.cpu_usage=cpu_usage
				if "ram_usage" in request.data:
					ram_usage=request.data.get("ram_usage")
					nodeO.ram_usage=ram_usage
					node_logO.ram_usage=ram_usage
				if "current_video_status" in request.data:
					current_video_status=request.data.get("current_video_status")
					nodeO.current_video_status=current_video_status
				if "current_video_name" in request.data:
					current_video_name=request.data.get("current_video_name")
					nodeO.current_video_name=current_video_name
				if "current_video_number" in request.data:
					current_video_number=request.data.get("current_video_number")
					nodeO.current_video_number=current_video_number
				if "current_timestamp" in request.data:
					current_timestamp=request.data.get("current_timestamp")
					nodeO.current_timestamp=current_timestamp
				if "current_volume" in request.data:
					current_volume=request.data.get("current_volume")
					nodeO.current_volume=current_volume
				if "totalVideos" in request.data:
					total_videos=request.data.get("totalVideos")
					nodeO.total_videos=total_videos
				if "vduration" in request.data:
					video_duration=request.data.get("vduration")
					nodeO.video_duration=video_duration
				if "video_list" in request.data:
					video_list=request.data.get("video_list")
					nodeO.video_list=video_list
				nodeO.save()
				node_logO.save()
				if "command_log_id" in request.data:
					command_log_id=request.data.get("command_log_id")
					command_status=request.data.get("command_status")
					command_message=request.data.get("command_message")
					command_logO=CommandLog.objects.get(pk=command_log_id)
					# command_logO.status=command_status
					# command_logO.message=command_message
					# command_logO.updated_by=request.user
					# command_logO.save()
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status=command_status
					command_log_batchO.message=command_message
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()
					return Response({"message": "Heartbeat added Successfully and Command logs updated successfully."},status=HTTP_200_OK)
				else:
					return Response({"message": "Heartbeat added Successfully"},status=HTTP_200_OK)

		except:
			return Response({"message": "Server Crashed"},status=HTTP_200_OK) 


class command_log_api(APIView):
	permission_classes = (IsAuthenticated,)
	@csrf_exempt
	def post(self, request):
		try:
			print(request.data)
			if "command_log_id" in request.data:
				command_log_id=request.data.get("command_log_id")
				command_status=request.data.get("command_status")
				command_message=request.data.get("command_message")
				command_logO=CommandLog.objects.get(pk=command_log_id)
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status=command_status
				command_log_batchO.message=command_message
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()
				return Response({"message": "Command logs updated successfully."},status=HTTP_200_OK)
			else:
				return Response({"message": "Kindly Provide Command Log id"},status=HTTP_200_OK)
		except:
			return Response({"message": "Server Crashed"},status=HTTP_200_OK)


def login_view(request):
	context={}
	if request.user.is_authenticated and request.user.is_staff:
		return redirect("/project_selection/")
	if request.method=="POST":
		username=request.POST.get("username")
		password=request.POST.get("password")
		user=authenticate(username=username,password=password,is_staff=True)
		if user is not None:
			login(request, user)
			return redirect("/project_selection/")
		else:
			context['status']="email and password does not exists" 
		return render(request,"museum/login.html",context)
	else:
		return render(request,"museum/login.html",context)



@login_required()
@user_passes_test(lambda u: u.is_staff)
def project_selection(request):
	context={}
	if MMSUser.objects.filter(user=request.user).exists():

		mms_userO=MMSUser.objects.get(user=request.user)
		context['mms_user']=mms_userO
		projectO=Project.objects.filter(organization=mms_userO.organization)
		context['organization']=mms_userO.organization
		context['project_selection']=projectO
		if request.method=="POST":
			proj=request.POST.get('proj')
			projO=Project.objects.get(name=proj)
			return redirect("/"+str(mms_userO.organization.id)+"/"+str(projO.id)+"/dashboard/")


	return render(request,'museum/project_selection.html',context)

def device_status_check(node_id):
	if Node.objects.filter(pk=node_id).exists():
		nodeO=Node.objects.get(pk=node_id)
		if nodeO.updated_at>=timezone.now()-timezone.timedelta(seconds=131):
			return "online"
		else:
			return "offline"

	else:
		return "offline"


@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
@module_is_entry_mms_user
def dashboard(request,org_id,proj_id):
	context={}
	online_count=0
	offline_count=0
	not_configured_count=0
	all_count=0
	cpu_30=0
	cpu_60=0
	cpu_90=0
	cpu_100=0
	ram_30=0
	ram_60=0
	ram_90=0
	ram_100=0
	disk_30=0
	disk_60=0
	disk_90=0
	disk_100=0
	organizationO=Organization.objects.get(pk=org_id) 
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		if request.method=="GET" and request.is_ajax():
			nodes=Node.objects.filter(project=projectO).exclude(category__in=["PROJECTOR","PROJECTOR_B15"])
			for i in nodes:
				all_count=all_count+1
				if i.is_config==False:
					not_configured_count=not_configured_count+1
				elif device_status_check(i.pk)=="online":
					online_count=online_count+1
					node_logO=NodeLog.objects.filter(node=i).order_by('-id')[0]
					if node_logO.cpu_usage in range(0,30):
						cpu_30=cpu_30+1
					elif node_logO.cpu_usage in range(30,60):
						cpu_60=cpu_60+1
					elif node_logO.cpu_usage in range(60,90):
						cpu_90=cpu_90+1
					else:
						cpu_100=cpu_100+1
					if node_logO.disc_space_usage in range(0,30):
						disk_30=disk_30+1
					elif node_logO.disc_space_usage in range(30,60):
						disk_60=disk_60+1
					elif node_logO.disc_space_usage in range(60,90):
						disk_90=disk_90+1
					else:
						disk_100=disk_100+1
					if node_logO.ram_usage in range(0,30):
						ram_30=ram_30+1
					elif node_logO.ram_usage in range(30,60):
						ram_60=ram_60+1
					elif node_logO.ram_usage in range(60,90):
						ram_90=ram_90+1
					else:
						ram_100=ram_100+1
				else:
					offline_count=offline_count+1
				
			return JsonResponse({'online_count': online_count, 'offline_count' : offline_count, 'not_configured_count' : not_configured_count, 'all_count' : all_count, 'cpu_30' : cpu_30, 'cpu_60' : cpu_60, 'cpu_90' : cpu_90, 'cpu_100' : cpu_100, 'ram_30' : ram_30, 'ram_60' : ram_60, 'ram_90' : ram_90, 'ram_100' : ram_100, 'disk_30' : disk_30, 'disk_60' : disk_60, 'disk_90' : disk_90, 'disk_100' : disk_100})
			





	else:
		context['status']="You are not authorized for accessing other organization's Projects."

	return render(request,'museum/dashboard.html',context)



@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
@module_is_entry_mms_user
def devices(request,org_id,proj_id):
	context={}
	command_list=[]
	kwargs={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		nodeO=Node.objects.filter(project=projectO)
		context['devices']=nodeO
		commandO=Command.objects.filter(project=projectO).exclude(name__in=['SORT_CONTENT', 'SOFTWARE_UPDATE', 'DELETE_CONTENT', 'ADD_CONTENT'])
		context['command']=commandO
		floorO=Floor.objects.filter(project=projectO).order_by('name')
		context['floor']=floorO
		zoneO=Zone.objects.filter(project=projectO).order_by('name')
		context['zone']=zoneO
		exhibitO=Exhibit.objects.filter(project=projectO).order_by('name')
		context['exhibit']=exhibitO
		if request.method=='GET' and request.is_ajax():
			data=[]
			kwargs['{0}'.format('project')]= projectO

			if 'floor_id[]' in request.GET:
				floor_id=request.GET.getlist('floor_id[]')
				kwargs['{0}__{1}__{2}'.format('floor', 'pk', 'in')]= floor_id

			if 'zone_id[]' in request.GET:
				zone_id=request.GET.getlist('zone_id[]')
				kwargs['{0}__{1}__{2}'.format('zone', 'pk', 'in')]= zone_id

			if 'exhibit_id[]' in request.GET:
				exhibit_id=request.GET.getlist('exhibit_id[]')
				kwargs['{0}__{1}__{2}'.format('exhibit', 'pk', 'in')]= exhibit_id
			
			if 'status' in request.GET:
				status=request.GET.get('status')
				if status == 'online':
					kwargs['{0}__{1}'.format('updated_at','gt')]=timezone.now()-timezone.timedelta(seconds=131)
				elif status=="offline":
					kwargs['{0}'.format('is_config')]=True
					kwargs['{0}__{1}'.format('updated_at','lt')]=timezone.now()-timezone.timedelta(seconds=131)
				elif status=="not_configured":
					kwargs['{0}'.format('is_config')]=False
			
			nodeO=Node.objects.filter(**kwargs).exclude(category__in=["PROJECTOR","PROJECTOR_B15"])

			for i in commandO:
				command_list.append({'id' : i.pk, 'name' : i.name})

			for i in nodeO:
				if i.is_config==True:
					data.append({'id' : i.pk, 'name' : i.name, 'ip' : i.ip, 'floor' : i.floor.name, 'zone' : i.zone.name, 'exhibit' : i.exhibit.name, 'is_config' : i.is_config,'status' : device_status_check(i.pk), 'unique_reg_code' : i.unique_reg_code, 'mac_addr' : i.mac_addr, 'updated_at' : i.updated_at, 'version' : i.version })
				else:
					data.append({'id' : i.pk, 'name' : i.name, 'ip' : i.ip, 'is_config' : i.is_config, 'unique_reg_code' : i.unique_reg_code, 'mac_addr' : i.mac_addr, 'updated_at' :i.updated_at, 'version' : i.version, })

			return JsonResponse({'data': data, 'command' : command_list}) 

		elif request.method=="POST" and request.is_ajax() and "command_id" in request.POST:
			node_id=request.POST.getlist('node_id[]')
			command_id=request.POST.get('command_id')
			commandO=Command.objects.get(pk=command_id)
			if Node.objects.filter(pk__in=node_id).exists():
				nodeO=Node.objects.filter(pk__in=node_id)
				for i in nodeO:
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					if commandO.name == "TurnOn":
						send_magic_packet(i.mac_addr)
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TurnOn Command sent successfully"
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
					else:
						tcp = TCPClient()
						tcp_response = tcp.sendTcpCommand(i.ip,i.port,commandO.name+' '+str(command_logO.pk))

						if tcp_response==True:
							command_log_batchO=CommandLogBatch.objects.create()
							command_log_batchO.command_log=command_logO
							command_log_batchO.status="SUCCESS"
							command_log_batchO.message="TCP Request sent successfully."
							command_log_batchO.updated_by=request.user
							command_log_batchO.save()
							# command_logO.status="SUCCESS"
							# command_logO.message="TCP Request sent successfully."
							# command_logO.save()
						
						else:
							command_log_batchO=CommandLogBatch.objects.create()
							command_log_batchO.command_log=command_logO
							command_log_batchO.status="FAILED"
							command_log_batchO.message=tcp_response
							command_log_batchO.updated_by=request.user
							command_log_batchO.save()
							# command_logO.status="FAILED"
							# command_logO.message=tcp_response
							# command_logO.save()
				return JsonResponse({'status':"Command Logs has been created. Go to Command Logs for more details."})
					
			else:
				return JsonResponse({'status':"Please Select the node to send the commands"})

		# elif request.method=="POST" and request.is_ajax() and 'device'

		elif request.method=="POST" and request.is_ajax() and 'floor_id' in request.POST:
			zones=[]
			floor_id=request.POST.get('floor_id')
			if Floor.objects.filter(pk=floor_id).exists():
				floorO=Floor.objects.get(pk=floor_id)
				zoneO=Zone.objects.filter(floor=floorO)
				for i in zoneO:
					zones.append({'id' : i.pk, 'name' : i.name})
				return JsonResponse({'data': zones})
			else:
				return JsonResponse({'message': "Please select a valid Floor."})


		elif request.method=="POST" and request.is_ajax() and 'zone_id' in request.POST:
			exhibits=[]
			zone_id=request.POST.get('zone_id')
			if Zone.objects.filter(pk=zone_id).exists():
				zoneO=Zone.objects.get(pk=zone_id)
				exhibitO=Exhibit.objects.filter(zone=zoneO)
				for i in exhibitO:
					exhibits.append({'id' : i.pk, 'name' : i.name})
				return JsonResponse({'data': exhibits})
			else:
				return JsonResponse({'message': "Please select a valid zone."})

		elif request.method=="POST" and request.is_ajax() and  'single_node_id' in request.POST:
			single_node_id=request.POST.get('single_node_id')
			floor=request.POST.get('floor')
			zone=request.POST.get('zone')
			exhibit=request.POST.get('exhibit')
			name=request.POST.get('name')
			heartbeat_rate=request.POST.get('heartbeat_rate')
			if single_node_id !="" and single_node_id != None and floor != "" and floor != None and zone!="" and zone!=None and exhibit!="" and exhibit!=None and name!="" and name!=None and heartbeat_rate!="" and heartbeat_rate!=None:
				floorO=Floor.objects.get(pk=floor)
				zoneO=Zone.objects.get(pk=zone)
				exhibitO=Exhibit.objects.get(pk=exhibit)
				nodeO=Node.objects.get(pk=single_node_id)
				nodeO.project=projectO
				nodeO.floor=floorO
				nodeO.zone=zoneO
				nodeO.exhibit=exhibitO
				nodeO.name=name
				nodeO.heartbeat_rate=heartbeat_rate
				nodeO.is_config=True
				nodeO.save()
				return JsonResponse({'status':"Device Configured successfully."})
			else:
				return JsonResponse({'status':"Please fill all the details while configuring the device."})
		elif request.method=="POST" and "shutdown_all" in request.POST:
			nodeO=Node.objects.filter(category__in=["NUC","SOC","WATCHOUT","PROJECTOR","PROJECTOR_B15","INTERACTIVE"])
			commandO=Command.objects.get(name="shutdown")
			for i in nodeO:
				if device_status_check(i.pk) =="online" and i.category in ["NUC","SOC","WATCHOUT","INTERACTIVE"]:
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,commandO.name+' '+str(command_logO.pk))
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()

				elif i.category =="PROJECTOR":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,"%1POWR 0\r")
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()


				#elif i.category =="PROJECTOR_B15":
				#	command_logO=CommandLog.objects.create()
				#	command_logO.command=commandO
				#	command_logO.node=i
				#	command_logO.created_by=request.user
				#	command_logO.updated_by=request.user
				#	command_logO.save()
				#	url = "http://192.168.1.33:9090"
				#	payload = {
       				#	 "jsonrpc": "2.0",
       				#	 "method": "system.poweroff",
    				#		}
				#	response = requests.post(url,json=payload,timeout=0.1)
				#	command_log_batchO=CommandLogBatch.objects.create()
				#	command_log_batchO.command_log=command_logO
				#	command_log_batchO.status="SUCCESS"
				#	command_log_batchO.message="Projector shut down successfully."
				#	command_log_batchO.updated_by=request.user
				#	command_log_batchO.save()

				#context['status']="Command Logs has been created. Go to Command Logs for more details."

		elif request.method=="POST" and "TurnOn_all" in request.POST:
			nodeO=Node.objects.filter(category__in=["NUC","SOC","WATCHOUT","PROJECTOR","PROJECTOR_B15","INTERACTIVE"])
			commandO=Command.objects.get(name="TurnOn")
			for i in nodeO:
				if i.category in ["NUC","SOC","WATCHOUT","INTERACTIVE"]:
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					send_magic_packet(i.mac_addr)
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status="SUCCESS"
					command_log_batchO.message="TurnOn Command sent successfully"
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()

				elif i.category =="PROJECTOR":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,"%1POWR 1\r")
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()
				#elif i.category =="PROJECTOR_B15":
				#	command_logO=CommandLog.objects.create()
				#	command_logO.command=commandO
				#	command_logO.node=i
				#	command_logO.created_by=request.user
				#	command_logO.updated_by=request.user
				#	command_logO.save()
				#	url = "http://192.168.1.33:9090"
				#	payload = {
       				#	 "jsonrpc": "2.0",
       				#	 "method": "system.poweron",
    				#		}
				#	response = requests.post(url,json=payload,timeout=0.1)
				#	command_log_batchO=CommandLogBatch.objects.create()
				#	command_log_batchO.command_log=command_logO
				#	command_log_batchO.status="SUCCESS"
				#	command_log_batchO.message="Projector shut down successfully."
				#	command_log_batchO.updated_by=request.user
				#	command_log_batchO.save()

				context['status']="Command Logs has been created. Go to Command Logs for more details."
		


	else:
		context['status']="You are not authorized for accessing other organization's Projects."


	return render(request,'museum/device_list.html',context)



@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
@module_is_entry_mms_user
def devices_v2(request,org_id,proj_id):
	context={}
	command_list=[]
	kwargs={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		nodeO=Node.objects.filter(project=projectO)
		context['devices']=nodeO
		commandO=Command.objects.filter(project=projectO).exclude(name__in=['SORT_CONTENT', 'SOFTWARE_UPDATE', 'DELETE_CONTENT', 'ADD_CONTENT'])
		context['command']=commandO
		floorO=Floor.objects.filter(project=projectO).order_by('name')
		context['floor']=floorO
		zoneO=Zone.objects.filter(project=projectO).order_by('name')
		context['zone']=zoneO
		exhibitO=Exhibit.objects.filter(project=projectO).order_by('name')
		context['exhibit']=exhibitO
		if request.method=='GET' and request.is_ajax():
			data=[]
			kwargs['{0}'.format('project')]= projectO

			if 'floor_id[]' in request.GET:
				floor_id=request.GET.getlist('floor_id[]')
				kwargs['{0}__{1}__{2}'.format('floor', 'pk', 'in')]= floor_id

			if 'zone_id[]' in request.GET:
				zone_id=request.GET.getlist('zone_id[]')
				kwargs['{0}__{1}__{2}'.format('zone', 'pk', 'in')]= zone_id

			if 'exhibit_id[]' in request.GET:
				exhibit_id=request.GET.getlist('exhibit_id[]')
				kwargs['{0}__{1}__{2}'.format('exhibit', 'pk', 'in')]= exhibit_id
			
			if 'status' in request.GET:
				status=request.GET.get('status')
				if status == 'online':
					kwargs['{0}__{1}'.format('updated_at','gt')]=timezone.now()-timezone.timedelta(seconds=131)
				elif status=="offline":
					kwargs['{0}'.format('is_config')]=True
					kwargs['{0}__{1}'.format('updated_at','lt')]=timezone.now()-timezone.timedelta(seconds=131)
				elif status=="not_configured":
					kwargs['{0}'.format('is_config')]=False
			
			nodeO=Node.objects.filter(**kwargs).exclude(category__in=["PROJECTOR","PROJECTOR_B15"])

			for i in commandO:
				command_list.append({'id' : i.pk, 'name' : i.name})

			for i in nodeO:
				if i.is_config==True:
					data.append({'id' : i.pk, 'name' : i.name, 'ip' : i.ip, 'floor' : i.floor.name, 'zone' : i.zone.name, 'exhibit' : i.exhibit.name, 'is_config' : i.is_config,'status' : device_status_check(i.pk), 'unique_reg_code' : i.unique_reg_code, 'mac_addr' : i.mac_addr, 'updated_at' : i.updated_at, 'version' : i.version })
				else:
					data.append({'id' : i.pk, 'name' : i.name, 'ip' : i.ip, 'is_config' : i.is_config, 'unique_reg_code' : i.unique_reg_code, 'mac_addr' : i.mac_addr, 'updated_at' :i.updated_at, 'version' : i.version, })

			return JsonResponse({'data': data, 'command' : command_list}) 

		elif request.method=="POST" and request.is_ajax() and "command_id" in request.POST:
			node_id=request.POST.getlist('node_id[]')
			command_id=request.POST.get('command_id')
			commandO=Command.objects.get(pk=command_id)
			if Node.objects.filter(pk__in=node_id).exists():
				nodeO=Node.objects.filter(pk__in=node_id)
				for i in nodeO:
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					if commandO.name == "TurnOn":
						send_magic_packet(i.mac_addr)
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TurnOn Command sent successfully"
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
					else:
						tcp = EncryptedTCPClient()
						tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt((commandO.name+' '+str(command_logO.pk)).encode(),RSA.importKey(i.pem_file)))

						if tcp_response==True:
							command_log_batchO=CommandLogBatch.objects.create()
							command_log_batchO.command_log=command_logO
							command_log_batchO.status="SUCCESS"
							command_log_batchO.message="TCP Request sent successfully."
							command_log_batchO.updated_by=request.user
							command_log_batchO.save()
							# command_logO.status="SUCCESS"
							# command_logO.message="TCP Request sent successfully."
							# command_logO.save()
						
						else:
							command_log_batchO=CommandLogBatch.objects.create()
							command_log_batchO.command_log=command_logO
							command_log_batchO.status="FAILED"
							command_log_batchO.message=tcp_response
							command_log_batchO.updated_by=request.user
							command_log_batchO.save()
							# command_logO.status="FAILED"
							# command_logO.message=tcp_response
							# command_logO.save()
				return JsonResponse({'status':"Command Logs has been created. Go to Command Logs for more details."})
					
			else:
				return JsonResponse({'status':"Please Select the node to send the commands"})

		# elif request.method=="POST" and request.is_ajax() and 'device'

		elif request.method=="POST" and request.is_ajax() and 'floor_id' in request.POST:
			zones=[]
			floor_id=request.POST.get('floor_id')
			if Floor.objects.filter(pk=floor_id).exists():
				floorO=Floor.objects.get(pk=floor_id)
				zoneO=Zone.objects.filter(floor=floorO)
				for i in zoneO:
					zones.append({'id' : i.pk, 'name' : i.name})
				return JsonResponse({'data': zones})
			else:
				return JsonResponse({'message': "Please select a valid Floor."})


		elif request.method=="POST" and request.is_ajax() and 'zone_id' in request.POST:
			exhibits=[]
			zone_id=request.POST.get('zone_id')
			if Zone.objects.filter(pk=zone_id).exists():
				zoneO=Zone.objects.get(pk=zone_id)
				exhibitO=Exhibit.objects.filter(zone=zoneO)
				for i in exhibitO:
					exhibits.append({'id' : i.pk, 'name' : i.name})
				return JsonResponse({'data': exhibits})
			else:
				return JsonResponse({'message': "Please select a valid zone."})

		elif request.method=="POST" and request.is_ajax() and  'single_node_id' in request.POST:
			single_node_id=request.POST.get('single_node_id')
			floor=request.POST.get('floor')
			zone=request.POST.get('zone')
			exhibit=request.POST.get('exhibit')
			name=request.POST.get('name')
			heartbeat_rate=request.POST.get('heartbeat_rate')
			if single_node_id !="" and single_node_id != None and floor != "" and floor != None and zone!="" and zone!=None and exhibit!="" and exhibit!=None and name!="" and name!=None and heartbeat_rate!="" and heartbeat_rate!=None:
				floorO=Floor.objects.get(pk=floor)
				zoneO=Zone.objects.get(pk=zone)
				exhibitO=Exhibit.objects.get(pk=exhibit)
				nodeO=Node.objects.get(pk=single_node_id)
				nodeO.project=projectO
				nodeO.floor=floorO
				nodeO.zone=zoneO
				nodeO.exhibit=exhibitO
				nodeO.name=name
				nodeO.heartbeat_rate=heartbeat_rate
				nodeO.is_config=True
				nodeO.save()
				return JsonResponse({'status':"Device Configured successfully."})
			else:
				return JsonResponse({'status':"Please fill all the details while configuring the device."})
		elif request.method=="POST" and "shutdown_all" in request.POST:
			nodeO=Node.objects.filter(category__in=["NUC","SOC","WATCHOUT","PROJECTOR","PROJECTOR_B15","INTERACTIVE"])
			commandO=Command.objects.get(name="shutdown")
			for i in nodeO:
				if device_status_check(i.pk) =="online" and i.category in ["NUC","SOC","WATCHOUT","INTERACTIVE"]:
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = EncryptedTCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt((commandO.name+' '+str(command_logO.pk)).encode(),RSA.importKey(i.pem_file)))
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()

				elif i.category =="PROJECTOR":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,"%1POWR 0\r")
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()


				#elif i.category =="PROJECTOR_B15":
				#	command_logO=CommandLog.objects.create()
				#	command_logO.command=commandO
				#	command_logO.node=i
				#	command_logO.created_by=request.user
				#	command_logO.updated_by=request.user
				#	command_logO.save()
				#	url = "http://192.168.1.33:9090"
				#	payload = {
       				#	 "jsonrpc": "2.0",
       				#	 "method": "system.poweroff",
    				#		}
				#	response = requests.post(url,json=payload,timeout=0.1)
				#	command_log_batchO=CommandLogBatch.objects.create()
				#	command_log_batchO.command_log=command_logO
				#	command_log_batchO.status="SUCCESS"
				#	command_log_batchO.message="Projector shut down successfully."
				#	command_log_batchO.updated_by=request.user
				#	command_log_batchO.save()

				#context['status']="Command Logs has been created. Go to Command Logs for more details."

		elif request.method=="POST" and "TurnOn_all" in request.POST:
			nodeO=Node.objects.filter(category__in=["NUC","SOC","WATCHOUT","PROJECTOR","PROJECTOR_B15","INTERACTIVE"])
			commandO=Command.objects.get(name="TurnOn")
			for i in nodeO:
				if i.category in ["NUC","SOC","WATCHOUT","INTERACTIVE"]:
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					send_magic_packet(i.mac_addr)
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status="SUCCESS"
					command_log_batchO.message="TurnOn Command sent successfully"
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()

				elif i.category =="PROJECTOR":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,"%1POWR 1\r")
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()
				#elif i.category =="PROJECTOR_B15":
				#	command_logO=CommandLog.objects.create()
				#	command_logO.command=commandO
				#	command_logO.node=i
				#	command_logO.created_by=request.user
				#	command_logO.updated_by=request.user
				#	command_logO.save()
				#	url = "http://192.168.1.33:9090"
				#	payload = {
       				#	 "jsonrpc": "2.0",
       				#	 "method": "system.poweron",
    				#		}
				#	response = requests.post(url,json=payload,timeout=0.1)
				#	command_log_batchO=CommandLogBatch.objects.create()
				#	command_log_batchO.command_log=command_logO
				#	command_log_batchO.status="SUCCESS"
				#	command_log_batchO.message="Projector shut down successfully."
				#	command_log_batchO.updated_by=request.user
				#	command_log_batchO.save()

				context['status']="Command Logs has been created. Go to Command Logs for more details."
		


	else:
		context['status']="You are not authorized for accessing other organization's Projects."


	return render(request,'museum/device_list_v2.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
@module_is_entry_mms_user
def control_panel(request,org_id,proj_id):
	context={}
	command_list=[]
	kwargs={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		nodeO=Node.objects.filter(project=projectO)
		context['devices']=nodeO
		commandO=Command.objects.filter(project=projectO).exclude(name__in=['SORT_CONTENT', 'SOFTWARE_UPDATE', 'DELETE_CONTENT', 'ADD_CONTENT'])
		context['command']=commandO
		floorO=Floor.objects.filter(project=projectO).order_by('name')
		context['floor']=floorO
		zoneO=Zone.objects.filter(project=projectO).order_by('name')
		context['zone']=zoneO
		exhibitO=Exhibit.objects.filter(project=projectO).order_by('name')
		context['exhibit']=exhibitO
		if request.method=='GET' and request.is_ajax():
			data=[]
			kwargs['{0}'.format('project')]= projectO
			kwargs['{0}'.format('is_config')]= True
			kwargs['{0}__{1}'.format('zone','in')]= mms_userO.zone.all()

			if 'floor_id[]' in request.GET:
				floor_id=request.GET.getlist('floor_id[]')
				kwargs['{0}__{1}__{2}'.format('floor', 'pk', 'in')]= floor_id

			if 'zone_id[]' in request.GET:
				zone_id=request.GET.getlist('zone_id[]')
				kwargs['{0}__{1}__{2}'.format('zone', 'pk', 'in')]= zone_id

			if 'exhibit_id[]' in request.GET:
				exhibit_id=request.GET.getlist('exhibit_id[]')
				kwargs['{0}__{1}__{2}'.format('exhibit', 'pk', 'in')]= exhibit_id
			
			if 'status' in request.GET:
				status=request.GET.get('status')
				if status == 'online':
					kwargs['{0}__{1}'.format('updated_at','gt')]=timezone.now()-timezone.timedelta(seconds=131)
				elif status=="offline":
					kwargs['{0}__{1}'.format('updated_at','lt')]=timezone.now()-timezone.timedelta(seconds=131)

			if 'name' in request.GET:
				name=request.GET.get('name')
				kwargs['{0}__{1}'.format('name', 'icontains')]=name
			
			nodeO=Node.objects.filter(**kwargs).order_by('sequence_id').exclude(category__in=["INTERACTIVE","PROJECTOR"])

			for i in commandO:
				command_list.append({'id' : i.pk, 'name' : i.name})

			for i in nodeO:
				if i.video_list:
					data.append({'id' : i.pk, 'name' : i.name, 'ip' : i.ip, 'floor' : i.floor.name, 'zone' : i.zone.name, 'exhibit' : i.exhibit.name,'status' : device_status_check(i.pk), 'unique_reg_code' : i.unique_reg_code, 'mac_addr' : i.mac_addr, 'updated_at' : i.updated_at, 'version' : i.version, 'current_video_status' : i.current_video_status, 'current_video_name' : i.current_video_name, 'current_video_number' : i.current_video_number, 'current_timestamp' : i.current_timestamp,'current_volume' : i.current_volume, "total_videos" : i.total_videos, 'video_duration' : i.video_duration, 'video_list' : eval(i.video_list)})
				else:
					data.append({'id' : i.pk, 'name' : i.name, 'ip' : i.ip, 'floor' : i.floor.name, 'zone' : i.zone.name, 'exhibit' : i.exhibit.name,'status' : device_status_check(i.pk), 'unique_reg_code' : i.unique_reg_code, 'mac_addr' : i.mac_addr, 'updated_at' : i.updated_at, 'version' : i.version, 'current_video_status' : i.current_video_status, 'current_video_name' : i.current_video_name, 'current_video_number' : i.current_video_number, 'current_timestamp' : i.current_timestamp,'current_volume' : i.current_volume, "total_videos" : i.total_videos, 'video_duration' : i.video_duration, 'video_list' : i.video_list})

				

			return JsonResponse({'data': data, 'command' : command_list}) 

		elif request.method=="POST" and request.is_ajax() and "command_id" in request.POST:
			node_id=request.POST.getlist('node_id[]')
			command_id=request.POST.get('command_id')
			volume_number=request.POST.get('volume_number')
			video_name=request.POST.get('video_name')
			gotoTime=request.POST.get('gotoTime')
			commandO=Command.objects.get(pk=command_id)
			if Node.objects.filter(pk__in=node_id).exists():
				nodeO=Node.objects.filter(pk__in=node_id)
				for i in nodeO:
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					if commandO.name=="VOLUME":
						tcp_response = tcp.sendTcpCommand(i.ip,i.port,commandO.name+' '+str(command_logO.pk)+' '+str(volume_number))
					elif commandO.name=="playByName":
						tcp_response = tcp.sendTcpCommand(i.ip,i.port,commandO.name+' '+str(command_logO.pk)+' '+str(video_name))
					elif commandO.name=="gotoTime":
						tcp_response = tcp.sendTcpCommand(i.ip,i.port,commandO.name+' '+str(command_logO.pk)+' '+str(gotoTime))
					elif commandO.name=="nextVideo" and i.category=="WATCHOUT":
						if WatchoutVideo.objects.filter(node=i).exists():
							watchout_video_count=WatchoutVideo.objects.filter(node=i).count()
							if watchout_video_count == 1:
								tcp_response = tcp.sendTcpCommand(i.ip,i.port,'gotoTime '+str(command_logO.pk)+' '+str(0))
							elif watchout_video_count == 2:
								tcp_response_timestamp = tcp.sendTcpCommandTimestamp(i.ip,i.port,'timestamp')
								watchout_videoO=WatchoutVideo.objects.get(node=i,video_position=1)
								if tcp_response_timestamp >= watchout_videoO.video_duration:
									tcp_response = tcp.sendTcpCommand(i.ip,i.port,'gotoTime '+str(command_logO.pk)+' '+str(0))
								else:
									tcp_response = tcp.sendTcpCommand(i.ip,i.port,'gotoTime '+str(command_logO.pk)+' '+str(watchout_videoO.video_duration))

							elif watchout_video_count == 3:
								tcp_response_timestamp = tcp.sendTcpCommandTimestamp(i.ip,i.port,'timestamp')
								watchout_video_1O=WatchoutVideo.objects.get(node=i,video_position=1)
								watchout_video_2O=WatchoutVideo.objects.get(node=i,video_position=2)
								if tcp_response_timestamp >= watchout_video_1O.video_duration:
									
									if tcp_response_timestamp >= watchout_video_1O.video_duration+watchout_video_2O.video_duration:
										tcp_response = tcp.sendTcpCommand(i.ip,i.port,'gotoTime '+str(command_logO.pk)+' '+str(0))
									else:
										tcp_response = tcp.sendTcpCommand(i.ip,i.port,'gotoTime '+str(command_logO.pk)+' '+str(watchout_video_1O.video_duration+watchout_video_2O.video_duration))

								else:
									tcp_response = tcp.sendTcpCommand(i.ip,i.port,'gotoTime '+str(command_logO.pk)+' '+str(watchout_video_1O.video_duration))
							
					elif commandO.name=="previousVideo" and i.category=="WATCHOUT":
						if WatchoutVideo.objects.filter(node=i).exists():
							watchout_video_count=WatchoutVideo.objects.filter(node=i).count()
							if watchout_video_count == 1:
								tcp_response = tcp.sendTcpCommand(i.ip,i.port,'gotoTime '+str(command_logO.pk)+' '+str(0))
							elif watchout_video_count == 2:
								tcp_response_timestamp = tcp.sendTcpCommandTimestamp(i.ip,i.port,'timestamp')
								watchout_videoO=WatchoutVideo.objects.get(node=i,video_position=1)
								if tcp_response_timestamp >= watchout_videoO.video_duration:
									tcp_response = tcp.sendTcpCommand(i.ip,i.port,'gotoTime '+str(command_logO.pk)+' '+str(0))
								else:
									tcp_response = tcp.sendTcpCommand(i.ip,i.port,'gotoTime '+str(command_logO.pk)+' '+str(watchout_videoO.video_duration))

							elif watchout_video_count == 3:
								tcp_response_timestamp = tcp.sendTcpCommandTimestamp(i.ip,i.port,'timestamp')
								watchout_video_1O=WatchoutVideo.objects.get(node=i,video_position=1)
								watchout_video_2O=WatchoutVideo.objects.get(node=i,video_position=2)
								if tcp_response_timestamp >= watchout_video_1O.video_duration:
									
									if tcp_response_timestamp >= watchout_video_1O.video_duration+watchout_video_2O.video_duration:
										tcp_response = tcp.sendTcpCommand(i.ip,i.port,'gotoTime '+str(command_logO.pk)+' '+str(watchout_video_1O.video_duration))
									else:
										tcp_response = tcp.sendTcpCommand(i.ip,i.port,'gotoTime '+str(command_logO.pk)+' '+str(0))

								else:
									tcp_response = tcp.sendTcpCommand(i.ip,i.port,'gotoTime '+str(command_logO.pk)+' '+str(watchout_video_1O.video_duration+watchout_video_2O.video_duration))	

							
					else:
						tcp_response = tcp.sendTcpCommand(i.ip,i.port,commandO.name+' '+str(command_logO.pk))

					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()
				return JsonResponse({'status':"Command Logs has been created. Go to Command Logs for more details."})
					
			else:
				return JsonResponse({'status':"Please Select the node to send the commands"})

		# elif request.method=="POST" and request.is_ajax() and 'device'
		elif request.method=="POST" and "halt_all" in request.POST:
			nodeO=Node.objects.filter(category__in=["NUC","SOC","WATCHOUT"])
			commandO=Command.objects.get(name="halt")
			for i in nodeO:
				if device_status_check(i.pk) =="online":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,commandO.name+' '+str(command_logO.pk))
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()
				context['status']="Command Logs has been created. Go to Command Logs for more details."
		elif request.method=="POST" and "run_all" in request.POST:
			nodeO=Node.objects.filter(category__in=["NUC","SOC","WATCHOUT"])
			commandO=Command.objects.get(name="run")
			for i in nodeO:
				if device_status_check(i.pk) =="online":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,commandO.name+' '+str(command_logO.pk))
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()
				context['status']="Command Logs has been created. Go to Command Logs for more details."
		elif request.method=="POST" and "restart_all" in request.POST:
			nodeO=Node.objects.filter(category__in=["NUC","SOC","WATCHOUT"])
			commandO=Command.objects.get(name="restart")
			for i in nodeO:
				if device_status_check(i.pk) =="online":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,commandO.name+' '+str(command_logO.pk))
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()
				context['status']="Command Logs has been created. Go to Command Logs for more details."

		elif request.method=="POST" and "shutdown_all" in request.POST:
			nodeO=Node.objects.filter(category__in=["NUC","SOC","WATCHOUT","PROJECTOR","PROJECTOR_B15","INTERACTIVE"])
			commandO=Command.objects.get(name="shutdown")
			for i in nodeO:
				if device_status_check(i.pk) =="online" and i.category in ["NUC","SOC","WATCHOUT","INTERACTIVE"]:
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,commandO.name+' '+str(command_logO.pk))
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()

				elif i.category =="PROJECTOR":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,"%1POWR 0\r")
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()


				elif i.category =="PROJECTOR_B15":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					url = "http://192.168.1.33:9090"
					payload = {
       					 "jsonrpc": "2.0",
       					 "method": "system.poweroff",
    						}
					response = requests.post(url,json=payload,timeout=0.1)
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status="SUCCESS"
					command_log_batchO.message="Projector shut down successfully."
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()

				context['status']="Command Logs has been created. Go to Command Logs for more details."

		elif request.method=="POST" and "TurnOn_all" in request.POST:
			nodeO=Node.objects.filter(category__in=["NUC","SOC","WATCHOUT","PROJECTOR","PROJECTOR_B15","INTERACTIVE"])
			commandO=Command.objects.get(name="TurnOn")
			for i in nodeO:
				if i.category in ["NUC","SOC","WATCHOUT","INTERACTIVE"]:
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					send_magic_packet(i.mac_addr)
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status="SUCCESS"
					command_log_batchO.message="TurnOn Command sent successfully"
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()

				elif i.category =="PROJECTOR":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,"%1POWR 1\r")
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()
				elif i.category =="PROJECTOR_B15":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					url = "http://192.168.1.33:9090"
					payload = {
       					 "jsonrpc": "2.0",
       					 "method": "system.poweron",
    						}
					response = requests.post(url,json=payload,timeout=0.1)
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status="SUCCESS"
					command_log_batchO.message="Projector shut down successfully."
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()

				context['status']="Command Logs has been created. Go to Command Logs for more details."

			
	else:
		context['status']="You are not authorized for accessing other organization's Projects."


	return render(request,'museum/control_panel.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
@module_is_entry_mms_user
def control_panel_v2(request,org_id,proj_id):
	context={}
	command_list=[]
	kwargs={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		nodeO=Node.objects.filter(project=projectO)
		context['devices']=nodeO
		commandO=Command.objects.filter(project=projectO).exclude(name__in=['SORT_CONTENT', 'SOFTWARE_UPDATE', 'DELETE_CONTENT', 'ADD_CONTENT'])
		context['command']=commandO
		floorO=Floor.objects.filter(project=projectO).order_by('name')
		context['floor']=floorO
		zoneO=Zone.objects.filter(project=projectO).order_by('name')
		context['zone']=zoneO
		exhibitO=Exhibit.objects.filter(project=projectO).order_by('name')
		context['exhibit']=exhibitO

		if request.method=="POST" and request.is_ajax() and "command_id" in request.POST:
			node_id=request.POST.getlist('node_id[]')
			command_id=request.POST.get('command_id')
			volume_number=request.POST.get('volume_number')
			video_name=request.POST.get('video_name')
			gotoTime=request.POST.get('gotoTime')
			commandO=Command.objects.get(pk=command_id)
			if Node.objects.filter(pk__in=node_id).exists():
				nodeO=Node.objects.filter(pk__in=node_id)
				for i in nodeO:
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = EncryptedTCPClient()
					if commandO.name=="VOLUME":
						tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt((commandO.name+' '+str(command_logO.pk)+' '+str(volume_number)).encode(),RSA.importKey(i.pem_file)))
					elif commandO.name=="playByName":
						tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt((commandO.name+' '+str(command_logO.pk)+' '+str(video_name)).encode(),RSA.importKey(i.pem_file)))
					elif commandO.name=="gotoTime":
						tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt((commandO.name+' '+str(command_logO.pk)+' '+str(gotoTime)).encode(),RSA.importKey(i.pem_file)))
					elif commandO.name=="nextVideo" and i.category=="WATCHOUT":
						if WatchoutVideo.objects.filter(node=i).exists():
							watchout_video_count=WatchoutVideo.objects.filter(node=i).count()
							if watchout_video_count == 1:
								tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt(('gotoTime '+str(command_logO.pk)+' '+str(0)).encode(),RSA.importKey(i.pem_file)))
							elif watchout_video_count == 2:
								tcp_response_timestamp = tcp.sendTcpCommandTimestamp(i.ip,i.encrypted_port,encrypt('timestamp'.encode(),RSA.importKey(i.pem_file)))
								watchout_videoO=WatchoutVideo.objects.get(node=i,video_position=1)
								if tcp_response_timestamp >= watchout_videoO.video_duration:
									tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt(('gotoTime '+str(command_logO.pk)+' '+str(0)).encode(),RSA.importKey(i.pem_file)))
								else:
									tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt(('gotoTime '+str(command_logO.pk)+' '+str(watchout_videoO.video_duration)).encode(),RSA.importKey(i.pem_file)))

							elif watchout_video_count == 3:
								tcp_response_timestamp = tcp.sendTcpCommandTimestamp(i.ip,i.encrypted_port,encrypt('timestamp'.encode(),RSA.importKey(i.pem_file)))
								watchout_video_1O=WatchoutVideo.objects.get(node=i,video_position=1)
								watchout_video_2O=WatchoutVideo.objects.get(node=i,video_position=2)
								if tcp_response_timestamp >= watchout_video_1O.video_duration:
									
									if tcp_response_timestamp >= watchout_video_1O.video_duration+watchout_video_2O.video_duration:
										tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt(('gotoTime '+str(command_logO.pk)+' '+str(0)).encode(),RSA.importKey(i.pem_file)))
									else:
										tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt(('gotoTime '+str(command_logO.pk)+' '+str(watchout_video_1O.video_duration+watchout_video_2O.video_duration)).encode(),RSA.importKey(i.pem_file)))

								else:
									tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt(('gotoTime '+str(command_logO.pk)+' '+str(watchout_video_1O.video_duration)).encode(),RSA.importKey(i.pem_file)))
							
					elif commandO.name=="previousVideo" and i.category=="WATCHOUT":
						if WatchoutVideo.objects.filter(node=i).exists():
							watchout_video_count=WatchoutVideo.objects.filter(node=i).count()
							if watchout_video_count == 1:
								tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt(('gotoTime '+str(command_logO.pk)+' '+str(0)).encode(),RSA.importKey(i.pem_file)))
							elif watchout_video_count == 2:
								tcp_response_timestamp = tcp.sendTcpCommandTimestamp(i.ip,i.encrypted_port,encrypt('timestamp'.encode(),RSA.importKey(i.pem_file)))
								watchout_videoO=WatchoutVideo.objects.get(node=i,video_position=1)
								if tcp_response_timestamp >= watchout_videoO.video_duration:
									tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt(('gotoTime '+str(command_logO.pk)+' '+str(0)).encode(),RSA.importKey(i.pem_file)))
								else:
									tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt(('gotoTime '+str(command_logO.pk)+' '+str(watchout_videoO.video_duration)).encode(),RSA.importKey(i.pem_file)))

							elif watchout_video_count == 3:
								tcp_response_timestamp = tcp.sendTcpCommandTimestamp(i.ip,i.encrypted_port,encrypt('timestamp'.encode(),RSA.importKey(i.pem_file)))
								watchout_video_1O=WatchoutVideo.objects.get(node=i,video_position=1)
								watchout_video_2O=WatchoutVideo.objects.get(node=i,video_position=2)
								if tcp_response_timestamp >= watchout_video_1O.video_duration:
									
									if tcp_response_timestamp >= watchout_video_1O.video_duration+watchout_video_2O.video_duration:
										tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt(('gotoTime '+str(command_logO.pk)+' '+str(watchout_video_1O.video_duration)).encode(),RSA.importKey(i.pem_file)))
									else:
										tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt(('gotoTime '+str(command_logO.pk)+' '+str(0)).encode(),RSA.importKey(i.pem_file)))

								else:
									tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt(('gotoTime '+str(command_logO.pk)+' '+str(watchout_video_1O.video_duration+watchout_video_2O.video_duration)).encode(),RSA.importKey(i.pem_file)))	

							
					else:
						tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt((commandO.name+' '+str(command_logO.pk)).encode(),RSA.importKey(i.pem_file)))

					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()
				return JsonResponse({'status':"Command Logs has been created. Go to Command Logs for more details."})
					
			else:
				return JsonResponse({'status':"Please Select the node to send the commands"})

		# elif request.method=="POST" and request.is_ajax() and 'device'
		elif request.method=="POST" and "halt_all" in request.POST:
			nodeO=Node.objects.filter(category__in=["NUC","SOC","WATCHOUT"])
			commandO=Command.objects.get(name="halt")
			for i in nodeO:
				if device_status_check(i.pk) =="online":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt((commandO.name+' '+str(command_logO.pk)).encode(),RSA.importKey(i.pem_file)))
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()
				context['status']="Command Logs has been created. Go to Command Logs for more details."
		elif request.method=="POST" and "run_all" in request.POST:
			nodeO=Node.objects.filter(category__in=["NUC","SOC","WATCHOUT"])
			commandO=Command.objects.get(name="run")
			for i in nodeO:
				if device_status_check(i.pk) =="online":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt((commandO.name+' '+str(command_logO.pk)).encode(),RSA.importKey(i.pem_file)))
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()
				context['status']="Command Logs has been created. Go to Command Logs for more details."
		elif request.method=="POST" and "restart_all" in request.POST:
			nodeO=Node.objects.filter(category__in=["NUC","SOC","WATCHOUT"])
			commandO=Command.objects.get(name="restart")
			for i in nodeO:
				if device_status_check(i.pk) =="online":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.encrypted_port,encrypt((commandO.name+' '+str(command_logO.pk)).encode(),RSA.importKey(i.pem_file)))
					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()
				context['status']="Command Logs has been created. Go to Command Logs for more details."


			
	else:
		context['status']="You are not authorized for accessing other organization's Projects."


	return render(request,'museum/control_panel_v2.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
def devices1(request,org_id,proj_id):
	context={}

	command_list=[]
	kwargs={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		nodeO=Node.objects.filter(project=projectO)
		context['devices']=nodeO
		commandO=Command.objects.filter(project=projectO).exclude(name__in=['SORT_CONTENT', 'SOFTWARE_UPDATE', 'DELETE_CONTENT', 'ADD_CONTENT'])
		context['command']=commandO
		floorO=Floor.objects.filter(project=projectO)
		context['floor']=floorO
		zoneO=Zone.objects.filter(project=projectO)
		context['zone']=zoneO
		exhibitO=Exhibit.objects.filter(project=projectO)
		context['exhibit']=exhibitO
		if request.method=='GET' and request.is_ajax():
			data=[]
			kwargs['{0}'.format('project')]= projectO

			if 'floor_id[]' in request.GET:
				floor_id=request.GET.getlist('floor_id[]')
				kwargs['{0}__{1}__{2}'.format('floor', 'pk', 'in')]= floor_id

			if 'zone_id[]' in request.GET:
				zone_id=request.GET.getlist('zone_id[]')
				kwargs['{0}__{1}__{2}'.format('zone', 'pk', 'in')]= zone_id

			if 'exhibit_id[]' in request.GET:
				exhibit_id=request.GET.getlist('exhibit_id[]')
				kwargs['{0}__{1}__{2}'.format('exhibit', 'pk', 'in')]= exhibit_id

			if 'id_status' in request.GET:
				id_status=request.GET.get('id_status')
				return JsonResponse({'status' : device_status_check(id_status) }) 

			nodeO=Node.objects.filter(**kwargs)
			

			for i in commandO:
				command_list.append({'id' : i.pk, 'name' : i.name})

			for i in nodeO:
				data.append({'id' : i.pk, 'name' : i.name, 'ip' : i.ip, 'floor' : i.floor.name, 'zone' : i.zone.name, 'exhibit' : i.exhibit.name, 'is_config' : i.is_config, 'status' : device_status_check(i.pk), 'heartbeat_rate' : i.heartbeat_rate })

			
			return JsonResponse({'data': data, 'command' : command_list}) 

		elif request.method=="POST" and request.is_ajax() and "command_id" in request.POST:
			node_id=request.POST.getlist('node_id[]')
			command_id=request.POST.get('command_id')
			commandO=Command.objects.get(pk=command_id)
			if Node.objects.filter(pk__in=node_id).exists():
				nodeO=Node.objects.filter(pk__in=node_id)
				for i in nodeO:
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,commandO.name+' '+str(command_logO.pk))

					if tcp_response==True:
						command_logO.status="SUCCESS"
						command_logO.message="TCP Request sent successfully."
						command_logO.save()
						
					else:
						command_logO.status="FAILED"
						command_logO.message=tcp_response
						command_logO.save()
				return JsonResponse({'status':"Command Logs has been created. Go to Command Logs for more details."})
					
			else:
				return JsonResponse({'status':"Please Select the node to send the commands"})

		# elif request.method=="POST" and request.is_ajax() and 'device'
		elif request.method=="POST" and request.is_ajax() and  'single_node_id' in request.POST:
			single_node_id=request.POST.get('single_node_id')
			project=request.POST.get('project_id')
			floor=request.POST.get('floor_id')
			zone=request.POST.get('zone_id')
			exhibit=request.POST.get('exhibit_id')
			name=request.POST.get('name')
			heartbeat_rate=request.POST.get('heartbeat_rate')
			projectO=Project.objects.get(pk=project)
			floorO=Floor.objects.get(pk=floor)
			zoneO=Zone.objects.get(pk=zone)
			exhibitO=Exhibit.objects.get(pk=exhibit)
			nodeO=Node.objects.get(pk=single_node_id)
			nodeO.project=projectO
			nodeO.floor=floorO
			nodeO.zone=zoneO
			nodeO.exhibit=exhibitO
			nodeO.name=name
			nodeO.heartbeat_rate=heartbeat_rate
			nodeO.save()
			return JsonResponse({'status':"Device Configured successfully."})




	else:
		context['status']="You are not authorized for accessing other organization's Projects."


	return render(request,'museum/device_list1.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
@module_is_entry_mms_user
def content_upload(request,org_id,proj_id):
	context={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		nodeO=Node.objects.filter(project=projectO)
		context['devices']=nodeO
		if request.method=="GET" and request.is_ajax():
			data=[]
			device_name=request.GET.get('device_name')
			if Node.objects.filter(pk=device_name).exists():
				nodeO=Node.objects.get(pk=device_name)
				node_fileO=NodeFile.objects.filter(node=nodeO).order_by('position')
				for i in node_fileO:
					data.append({"name" : i.node_file.name, "url" : i.node_file.url, "date" : i.created_at.date(), "file_pk" : i.pk,"size" : i.node_file.size})
				return JsonResponse({'data': data,"floor" : nodeO.floor.name,"zone" : nodeO.zone.name, "exhibit" : nodeO.exhibit.name})
				
			else:
				return JsonResponse({'status':"Please Select the node to see the files"})
		elif request.method=="POST" and request.is_ajax() and "device_name" in request.POST:
			file_array=[]
			device_name=request.POST.get('device_name')
			device_file=request.FILES.getlist('device_file')
			

			print("=-=-=-=-=0,",request.FILES)
			print(request.POST)
			print(device_name)
			print(device_file)
			if Node.objects.filter(pk=device_name).exists():
				nodeO=Node.objects.get(pk=device_name)
				for f in device_file:
					node_fileO=NodeFile.objects.create()
					node_fileO.node=nodeO
					node_fileO.node_file=f
					file_array.append(f.name)
					print(node_fileO,'--------------',file_array,f,"=====================",NodeFile.objects.filter(node=nodeO).exists(),"-=-=-",NodeFile)
					if NodeFile.objects.filter(node=nodeO).exists():
						print("----------------2046")
						previous_node_fileO=NodeFile.objects.filter(node=nodeO).order_by('-id')[0]
						node_fileO.position=previous_node_fileO.position+1
						node_fileO.save()
					else:
						node_fileO.position=1
						print("---------------2051",node_fileO,"--==",node_fileO.position)
						node_fileO.save()
						print("==============2054")
				commandO=Command.objects.get(name='ADD_CONTENT')
				command_logO=CommandLog.objects.create()
				command_logO.node=nodeO
				command_logO.command=commandO
				command_logO.created_by=request.user
				command_logO.updated_by=request.user
				command_logO.save()
				tcp = TCPClient()
				print("---------------2060",nodeO.ip, nodeO.port,'ADD_CONTENT '+str(command_logO.pk)+" "+str(file_array).replace("'",'"').replace(" ",""))
				tcp_response = tcp.sendTcpCommand(nodeO.ip, nodeO.port,'ADD_CONTENT '+str(command_logO.pk)+" "+str(file_array).replace("'",'"').replace(" ","") )
				print("-------------2064",tcp_response)
				if tcp_response==True:
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status="SUCCESS"
					command_log_batchO.message="TCP Request sent successfully."
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()
					# command_logO.status="SUCCESS"
					# command_logO.message="TCP Request sent successfully."
					# command_logO.save()
				
				else:
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status="FAILED"
					command_log_batchO.message=tcp_response
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()
					# command_logO.status="FAILED"
					# command_logO.message=tcp_response
					# command_logO.save()

				return JsonResponse({'status': "Files Saved Successfully."})
				
			else:
				return JsonResponse({'status': "Please Select the node first to upload the file."})

		elif request.method=="POST" and request.is_ajax() and "file_pk[]" in request.POST:
			#print(request.POST)
			#print('ajax2')
			message={}
			file_name=[]
			file_pk=request.POST.getlist('file_pk[]')
			device_id=request.POST.get("device_id")
			nodeO=Node.objects.get(pk=device_id)
			commandO=Command.objects.get(name='DELETE_CONTENT')
			node_fileO=NodeFile.objects.filter(pk__in=file_pk)
			for i in node_fileO:
				#print(i.node_file.name)
				file_name.append(i.node_file.name.split('/')[2])
				try:
					os.remove(i.node_file.path)
				except OSError:
					pass
				
				
				i.delete()
				#tcp = TCPClient()
				# tcp_response = tcp.sendTcpCommand(nodeO.ip, nodeO.port, "DELETE_CONTENT,")

				
			command_logO=CommandLog.objects.create()
			command_logO.node=nodeO
			command_logO.command=commandO
			command_logO.created_by=request.user
			command_logO.updated_by=request.user

			command_logO.save()
			tcp = TCPClient()
			tcp_response = tcp.sendTcpCommand(nodeO.ip, nodeO.port,'DELETE_CONTENT '+str(command_logO.pk)+" "+str(file_name).replace("'",'"').replace(" ",""))
			#print(type(tcp_response))
			if tcp_response==True:
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="SUCCESS"
				command_log_batchO.message="TCP Request sent successfully."
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()
				
				
				# command_logO.status="SUCCESS"
				# command_logO.message="TCP Request sent successfully."
				# command_logO.save()
				
			else:
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="FAILED"
				command_log_batchO.message=tcp_response
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()
				# command_logO.status="FAILED"
				# command_logO.message=tcp_response
				# command_logO.save()
			return JsonResponse({'status': "File Deleted Successfully"})

		elif request.method=="POST" and request.is_ajax() and "position_array[]" in request.POST:
			#print('ajax3')
			file_name=[]
			#print(request.POST)
			position_array=request.POST.getlist('position_array[]')
			#print(position_array)
			sort_commandO=Command.objects.get(name="SORT_CONTENT")
			
			for position, file_id in enumerate(position_array):
				node_fileO=NodeFile.objects.get(pk=file_id)
				node_fileO.position=position+1
				node_fileO.save()
				file_name.append(node_fileO.node_file.name.split('/')[2])
				nodeO=node_fileO.node
			command_logO=CommandLog.objects.create()
			command_logO.node=nodeO
			command_logO.command=sort_commandO
			command_logO.created_by=request.user
			command_logO.updated_by=request.user

			command_logO.save()
			tcp = TCPClient()
			tcp_response = tcp.sendTcpCommand(nodeO.ip, nodeO.port,sort_commandO.name+' '+str(command_logO.pk)+" "+str(file_name))
			#print(type(tcp_response))
			if tcp_response==True:
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="SUCCESS"
				command_log_batchO.message="TCP Request sent successfully."
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()
				# command_logO.status="SUCCESS"
				# command_logO.message="TCP Request sent successfully."
				# command_logO.save()
				
			else:
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="FAILED"
				command_log_batchO.message=tcp_response
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()
				# command_logO.status="FAILED"
				# command_logO.message=tcp_response
				# command_logO.save()
			return JsonResponse({'status': "Position Array Updated Successfully"})



		

	else:
		context['status']="You are not authorized for accessing other organization's Projects."


	return render(request,'museum/content_upload.html',context)	


@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
@module_is_entry_mms_user
def content_upload_v2(request,org_id,proj_id):
	context={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		nodeO=Node.objects.filter(project=projectO)
		context['devices']=nodeO
		if request.method=="GET" and request.is_ajax():
			data=[]
			device_name=request.GET.get('device_name')
			if Node.objects.filter(pk=device_name).exists():
				nodeO=Node.objects.get(pk=device_name)
				node_fileO=NodeFile.objects.filter(node=nodeO).order_by('position')
				for i in node_fileO:
					data.append({"name" : i.node_file.name, "url" : i.node_file.url, "date" : i.created_at.date(), "file_pk" : i.pk,"size" : i.node_file.size})
				return JsonResponse({'data': data,"floor" : nodeO.floor.name,"zone" : nodeO.zone.name, "exhibit" : nodeO.exhibit.name})
				
			else:
				return JsonResponse({'status':"Please Select the node to see the files"})
		elif request.method=="POST" and request.is_ajax() and "device_name" in request.POST:
			file_array=[]
			device_name=request.POST.get('device_name')
			device_file=request.FILES.getlist('device_file')
			

			# print(request.FILES)
			# print(request.POST)
			# print(device_name)
			# print(device_file)
			if Node.objects.filter(pk=device_name).exists():
				nodeO=Node.objects.get(pk=device_name)
				for f in device_file:
					node_fileO=NodeFile.objects.create()
					node_fileO.node=nodeO
					node_fileO.node_file=f
					file_array.append(f.name)
					if NodeFile.objects.filter(node=nodeO).exists():
						previous_node_fileO=NodeFile.objects.filter(node=nodeO).order_by('-id')[0]
						node_fileO.position=previous_node_fileO.position+1
						node_fileO.save()
					else:
						node_fileO.position=1
						node_fileO.save()
				commandO=Command.objects.get(name='ADD_CONTENT')
				command_logO=CommandLog.objects.create()
				command_logO.node=nodeO
				command_logO.command=commandO
				command_logO.created_by=request.user
				command_logO.updated_by=request.user
				command_logO.save()
				tcp = EncryptedTCPClient()
				tcp_response = tcp.sendTcpCommand(nodeO.ip, nodeO.encrypted_port,encrypt(('ADD_CONTENT '+str(command_logO.pk)+" "+str(file_array).replace("'",'"').replace(" ","")).encode(),RSA.importKey(nodeO.pem_file)))
				if tcp_response==True:
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status="SUCCESS"
					command_log_batchO.message="TCP Request sent successfully."
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()
					# command_logO.status="SUCCESS"
					# command_logO.message="TCP Request sent successfully."
					# command_logO.save()
				
				else:
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status="FAILED"
					command_log_batchO.message=tcp_response
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()
					# command_logO.status="FAILED"
					# command_logO.message=tcp_response
					# command_logO.save()

				return JsonResponse({'status': "Files Saved Successfully."})
				
			else:
				return JsonResponse({'status': "Please Select the node first to upload the file."})

		elif request.method=="POST" and request.is_ajax() and "file_pk[]" in request.POST:
			#print(request.POST)
			#print('ajax2')
			message={}
			file_name=[]
			file_pk=request.POST.getlist('file_pk[]')
			device_id=request.POST.get("device_id")
			nodeO=Node.objects.get(pk=device_id)
			commandO=Command.objects.get(name='DELETE_CONTENT')
			node_fileO=NodeFile.objects.filter(pk__in=file_pk)
			for i in node_fileO:
				#print(i.node_file.name)
				file_name.append(i.node_file.name.split('/')[2])
				try:
					os.remove(i.node_file.path)
				except OSError:
					pass
				
				
				i.delete()
				#tcp = TCPClient()
				# tcp_response = tcp.sendTcpCommand(nodeO.ip, nodeO.port, "DELETE_CONTENT,")

				
			command_logO=CommandLog.objects.create()
			command_logO.node=nodeO
			command_logO.command=commandO
			command_logO.created_by=request.user
			command_logO.updated_by=request.user
			command_logO.save()
			tcp = EncryptedTCPClient()
			tcp_response = tcp.sendTcpCommand(nodeO.ip, nodeO.encrypted_port,encrypt(('DELETE_CONTENT '+str(command_logO.pk)+" "+str(file_name).replace("'",'"').replace(" ","")).encode(),RSA.importKey(nodeO.pem_file)))
			#print(type(tcp_response))
			if tcp_response==True:
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="SUCCESS"
				command_log_batchO.message="TCP Request sent successfully."
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()
				
				
				# command_logO.status="SUCCESS"
				# command_logO.message="TCP Request sent successfully."
				# command_logO.save()
				
			else:
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="FAILED"
				command_log_batchO.message=tcp_response
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()
				# command_logO.status="FAILED"
				# command_logO.message=tcp_response
				# command_logO.save()
			return JsonResponse({'status': "File Deleted Successfully"})

		elif request.method=="POST" and request.is_ajax() and "position_array[]" in request.POST:
			#print('ajax3')
			file_name=[]
			#print(request.POST)
			position_array=request.POST.getlist('position_array[]')
			#print(position_array)
			sort_commandO=Command.objects.get(name="SORT_CONTENT")
			
			for position, file_id in enumerate(position_array):
				node_fileO=NodeFile.objects.get(pk=file_id)
				node_fileO.position=position+1
				node_fileO.save()
				file_name.append(node_fileO.node_file.name.split('/')[2])
				nodeO=node_fileO.node
			command_logO=CommandLog.objects.create()
			command_logO.node=nodeO
			command_logO.command=sort_commandO
			command_logO.created_by=request.user
			command_logO.updated_by=request.user
			command_logO.save()
			tcp = EncryptedTCPClient()
			tcp_response = tcp.sendTcpCommand(nodeO.ip, nodeO.encrypted_port,encrypt((sort_commandO.name+' '+str(command_logO.pk)+" "+str(file_name)).encode(),RSA.importKey(nodeO.pem_file)))
			#print(type(tcp_response))
			if tcp_response==True:
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="SUCCESS"
				command_log_batchO.message="TCP Request sent successfully."
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()
				# command_logO.status="SUCCESS"
				# command_logO.message="TCP Request sent successfully."
				# command_logO.save()
				
			else:
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="FAILED"
				command_log_batchO.message=tcp_response
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()
				# command_logO.status="FAILED"
				# command_logO.message=tcp_response
				# command_logO.save()
			return JsonResponse({'status': "Position Array Updated Successfully"})



		

	else:
		context['status']="You are not authorized for accessing other organization's Projects."


	return render(request,'museum/content_upload_v2.html',context)

@login_required()
@user_passes_test(lambda u: u.is_staff)
@module_is_entry_mms_user
def command_logs(request,org_id,proj_id):
	context={}
	data=[]
	kwargs={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		nodeO=Node.objects.filter(project=projectO)
		commandO=Command.objects.all()
		context['node']=nodeO
		context['command']=commandO
		if request.is_ajax():
			#print(request.GET)
			# for k,vals in request.GET.lists():
			# 	for v in vals:
			# 		print(v)
			if 'node_id[]' in request.GET:
				node_id=request.GET.getlist('node_id[]')
				kwargs['{0}__{1}__{2}'.format('node', 'pk', 'in')]= node_id
			if 'date_range[]' in request.GET:
				date_range=request.GET.getlist('date_range[]')
				kwargs['{0}__{1}'.format('created_at','range')]= [datetime.datetime.strptime(i,"%Y-%m-%d").date() for i in date_range]
			if 'command_id[]' in request.GET:
				command_id=request.GET.getlist('command_id[]')
				kwargs['{0}__{1}__{2}'.format('command', 'pk', 'in')]= command_id
			# if 'command_status[]' in request.GET:
			# 	command_status=request.GET.getlist('command_status[]')
			# 	kwargs['{0}__{1}'.format('status','in')]= command_status

			#print(kwargs)

			command_logO=CommandLog.objects.filter(**kwargs).order_by('-id')
			paginator = Paginator(command_logO, 25) # Show 25 commandlogs per page.
			page_number = request.GET.get('page')
			page_obj = paginator.get_page(page_number)
			for i in page_obj:
				multiple=[]
				command_log_batchO=CommandLogBatch.objects.filter(command_log=i).order_by('-id')
				for c in command_log_batchO:
					multiple.append({'status' : c.status, 'message' : c.message, 'updated_by' : c.updated_by.username, 'date' : c.updated_at })
					# status.append(c.status)
					# message.append(c.message)
					# updated_by.append(c.updated_by.is_staff)
					# updated_at.append(c.updated_at)

			

				data.append({'pk' : i.pk, 'device_name' : i.node.name, 'command_name' : i.command.name, 'multiple' : multiple, 'num_pages' : paginator.num_pages})

			return JsonResponse({'data': data})

			
			# if date_range:
			# 	print('if')
			# 	if CommandLog.objects.filter(Q(node__pk__in=node_id) | Q(command__pk__in=command_id) | Q(status__in=command_status) | Q(created_at__date__range=date_range)).exists():
			# 		command_logO=CommandLog.objects.filter(Q(node__pk__in=node_id) | Q(command__pk__in=command_id) | Q(status__in=command_status) | Q(created_at__date__range=date_range))
			# 		for i in command_logO:
			# 			data.append({'device_name' : i.node.name, 'command_name' : i.command.name, 'command_status' : i.status, 'message' : i.message, 'date' : i.created_at.date()})
			# 		return JsonResponse({'data': data})
			# 	else:
			# 		return JsonResponse({'status': "Command Logs does not exists"})
				

			# else:
			# 	print('else')
			# 	if CommandLog.objects.filter(Q(node__pk__in=node_id) | Q(command__pk__in=command_id) | Q(status__in=command_status)).exists():
			# 		print('if')
			# 		command_logO=CommandLog.objects.filter(Q(node__pk__in=node_id) | Q(command__pk__in=command_id) | Q(status__in=command_status))
			# 		for i in command_logO:
			# 			data.append({'device_name' : i.node.name, 'command_name' : i.command.name, 'command_status' : i.status, 'message' : i.message, 'date' : i.created_at.date()})
			# 		return JsonResponse({'data': data})
			# 	else:
			# 		print ('else2')
			# 		return JsonResponse({'status': "Command Logs does not exists"})
			
		context['status']="You are not authorized for accessing other organization's Projects."
	else:
		context['status']="You are not authorized for accessing other organization's Projects."
	return render(request,'museum/command_logs.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
@module_is_entry_mms_user
def reports(request,org_id,proj_id):
	context={}
	data=[]
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		if request.is_ajax():
			nodeO=Node.objects.filter(project=projectO,is_config=True).exclude(category__in=['PROJECTOR','PROJECTOR_B15'])
			if 'date_range[]' in request.GET:
				date_range=request.GET.getlist('date_range[]')
				print(date_range)
				date_range=[datetime.datetime.strptime(i,"%Y-%m-%d").date() for i in date_range]
				print(date_range)
				for i in nodeO:
					if Report.objects.filter(report_date__range=date_range).exists():
						online_percentage=Report.objects.filter(node=i,report_date__range=date_range).aggregate(Avg('online_percentage'))
						downtime=Report.objects.filter(node=i,report_date__range=date_range).aggregate(Sum('downtime'))
						data.append({'node_id' : i.pk,'device_name' : i.name, 'online_percentage' : online_percentage['online_percentage__avg'],'downtime' : downtime['downtime__sum']})
					else:
						#print("hi")
						# if ReportFailure.objects.filter(reason_date__range=date_range,node=i):
						#  	report_failureO=ReportFailure.objects.filter(reason_date__range=date_range,node=i)
							
						data.append({'node_id' : i.pk,'device_name' : i.name, 'online_percentage' : 0,'downtime' : 0})	
			return JsonResponse({'data': data})
	else:
		context['status']="You are not authorized for accessing other organization's Projects."
	return render(request,'museum/reports.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
@module_is_entry_mms_user
def downtime_detail(request,org_id,proj_id):
	context={}
	data=[]
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		if 'date_range' and 'node_id' in request.GET:
			print(request.GET)
			date_range=request.GET.get('date_range')
			node_id=request.GET.get('node_id')
			date_range=[datetime.datetime.strptime(i,"%Y-%m-%d").date() for i in date_range.split(',')]
			print(date_range)
			print(node_id)
			nodeO=Node.objects.get(pk=node_id)
			report_failureO=ReportFailure.objects.filter(reason_date__range=date_range,node=nodeO)
			context['report_failure']=report_failureO
			context['node']=nodeO
	else:
		context['status']="You are not authorized for accessing other organization's Projects."
	return render(request,'museum/downtime_detail.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
@module_is_entry_mms_user
def pm_count_analytics(request,org_id,proj_id):
	context={}
	data=[]
	pm_name=["SHRI JAWAHARLAL NEHRU", "SHRI GULZARILAL NANDA","SHRI LAL BAHADUR SHASTRI", "SMT. INDIRA GANDHI","SHRI MORARJI DESAI","SHRI CHARAN SINGH","SHRI RAJIV GANDHI", "SHRI VISHWANATH PRATAP SINGH","SHRI CHANDRA SHEKHAR","SHRI P.V. NARASIMHA RAO","SHRI H.D DEVE GOWDA","SHRI INDER KUMAR GUJRAL","SHRI ATAL BIHARI VAJPAYEE","DR. MANMOHAN SINGH","SHRI NARENDRA MODI"]
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		if request.is_ajax():
			if 'date_range[]' in request.GET:
				date_range=request.GET.getlist('date_range[]')
				date_range=[datetime.datetime.strptime(i,"%Y-%m-%d").date() for i in date_range]
				print(date_range)
				for i in pm_name:
					selfie_with_pm_count=PMSelection.objects.filter(pm_name=i,updated_at__range=date_range,category=1).count()
					walk_with_pm_count=PMSelection.objects.filter(pm_name=i,updated_at__range=date_range,category=2).count()
					data.append({'pm_name' : i,'selfie_with_pm_count' : selfie_with_pm_count,'walk_with_pm_count' : walk_with_pm_count })
			return JsonResponse({'data': data})
	else:
		context['status']="You are not authorized for accessing other organization's Projects."
	return render(request,'museum/pm_count_analytics.html',context)

@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
@module_is_entry_mms_user
def software_update(request,org_id,proj_id):
	context={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		nodeO=Node.objects.filter(project=projectO)
		context['devices']=nodeO
		if request.method=='POST' and request.is_ajax():

			#print(request.POST)
			#print(request.FILES)
			node_id=request.POST.getlist('node_id')
			device_software=request.FILES.getlist("device_software")
			nodeO=Node.objects.filter(pk__in=node_id)
			for i in nodeO:
				for f in device_software:
					node_softwareO=NodeSoftware.objects.create()
					node_softwareO.node=i
					node_softwareO.node_software=f
					node_softwareO.save()
				commandO=Command.objects.get(name='SOFTWARE_UPDATE')
				command_logO=CommandLog.objects.create()
				command_logO.node=i
				command_logO.command=commandO
				command_logO.created_by=request.user
				command_logO.updated_by=request.user
				command_logO.save()
				tcp = TCPClient()
				tcp_response = tcp.sendTcpCommand(i.ip, i.port,'SOFTWARE_UPDATE '+ str(command_logO.pk))
				if tcp_response==True:
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status="SUCCESS"
					command_log_batchO.message="TCP Request sent successfully."
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()
					# command_logO.status="SUCCESS"
					# command_logO.message="TCP Request sent successfully."

					# command_logO.save()
					
				else:
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status="FAILED"
					command_log_batchO.message=tcp_response
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()
					# command_logO.status="FAILED"
					# command_logO.message=tcp_response
					# command_logO.save()
				

			return JsonResponse({'status': "Command Logs has been created. Go to Command Logs for more details."})

		elif request.method=='GET' and request.is_ajax():
			node_id=request.GET.get('node_id')
			nodeO=Node.objects.get(pk=node_id)
			return JsonResponse({'version' : nodeO.version,"floor" : nodeO.floor.name,"zone" : nodeO.zone.name, "exhibit" : nodeO.exhibit.name})

	else:
		context['status']="You are not authorized for accessing other organization's Projects."

	

	return render(request,'museum/software_update.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
@module_is_entry_mms_user
def software_update_v2(request,org_id,proj_id):
	context={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		nodeO=Node.objects.filter(project=projectO)
		context['devices']=nodeO
		if request.method=='POST' and request.is_ajax():

			#print(request.POST)
			#print(request.FILES)
			node_id=request.POST.getlist('node_id')
			device_software=request.FILES.getlist("device_software")
			nodeO=Node.objects.filter(pk__in=node_id)
			for i in nodeO:
				for f in device_software:
					node_softwareO=NodeSoftware.objects.create()
					node_softwareO.node=i
					node_softwareO.node_software=f
					node_softwareO.save()
				commandO=Command.objects.get(name='SOFTWARE_UPDATE')
				command_logO=CommandLog.objects.create()
				command_logO.node=i
				command_logO.command=commandO
				command_logO.created_by=request.user
				command_logO.updated_by=request.user
				command_logO.save()
				tcp = EncryptedTCPClient()
				tcp_response = tcp.sendTcpCommand(i.ip, i.encrypted_port,encrypt(('SOFTWARE_UPDATE '+ str(command_logO.pk)).encode(),RSA.importKey(i.pem_file)))
				if tcp_response==True:
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status="SUCCESS"
					command_log_batchO.message="TCP Request sent successfully."
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()
					# command_logO.status="SUCCESS"
					# command_logO.message="TCP Request sent successfully."

					# command_logO.save()
					
				else:
					command_log_batchO=CommandLogBatch.objects.create()
					command_log_batchO.command_log=command_logO
					command_log_batchO.status="FAILED"
					command_log_batchO.message=tcp_response
					command_log_batchO.updated_by=request.user
					command_log_batchO.save()
					# command_logO.status="FAILED"
					# command_logO.message=tcp_response
					# command_logO.save()
				

			return JsonResponse({'status': "Command Logs has been created. Go to Command Logs for more details."})

		elif request.method=='GET' and request.is_ajax():
			node_id=request.GET.get('node_id')
			nodeO=Node.objects.get(pk=node_id)
			return JsonResponse({'version' : nodeO.version,"floor" : nodeO.floor.name,"zone" : nodeO.zone.name, "exhibit" : nodeO.exhibit.name})

	else:
		context['status']="You are not authorized for accessing other organization's Projects."

	

	return render(request,'museum/software_update_v2.html',context)



@login_required()
@user_passes_test(lambda u: u.is_staff)
def device_detail(request,org_id,proj_id,node_id):
	context={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	if projectO.organization==organizationO:
		nodeO=Node.objects.get(pk=node_id)
		node_logO=NodeLog.objects.filter(node=nodeO)
		#node_fileO=NodeFile.objects.filter(node=nodeO)
		context['node']=nodeO
		context['node_log']=node_logO
		floorO=Floor.objects.filter(project=projectO)
		context['floor']=floorO
		#context['node_file']=node_fileO
		if request.method=="GET" and request.is_ajax():
			cpu_usage=[]
			ram_usage=[]
			disk_usage=[]
			updated_at=[]
			for i in node_logO:
				cpu_usage.append(i.cpu_usage)
				ram_usage.append(i.ram_usage)
				disk_usage.append(i.disc_space_usage)
				updated_at.append(i.updated_at)
			return JsonResponse({'cpu_usage': cpu_usage, 'ram_usage' : ram_usage, 'disk_usage' : disk_usage, 'updated_at' : updated_at})

		elif request.method=="POST" and request.is_ajax() and 'floor_id' in request.POST:
			zones=[]
			floor_id=request.POST.get('floor_id')
			if Floor.objects.filter(pk=floor_id).exists():
				floorO=Floor.objects.get(pk=floor_id)
				zoneO=Zone.objects.filter(floor=floorO)
				for i in zoneO:
					zones.append({'id' : i.pk, 'name' : i.name})
				return JsonResponse({'data': zones})
			else:
				return JsonResponse({'message': "Please select a valid Floor."})


		elif request.method=="POST" and request.is_ajax() and 'zone_id' in request.POST:
			exhibits=[]
			zone_id=request.POST.get('zone_id')
			if Zone.objects.filter(pk=zone_id).exists():
				zoneO=Zone.objects.get(pk=zone_id)
				exhibitO=Exhibit.objects.filter(zone=zoneO)
				for i in exhibitO:
					exhibits.append({'id' : i.pk, 'name' : i.name})
				return JsonResponse({'data': exhibits})
			else:
				return JsonResponse({'message': "Please select a valid zone."})

		elif request.method=="POST":
			floor=request.POST.get('floor')
			zone=request.POST.get('zone')
			exhibit=request.POST.get('exhibit')
			name=request.POST.get('name')
			heartbeat_rate=request.POST.get('heartbeat_rate')
			floorO=Floor.objects.get(pk=floor)
			zoneO=Zone.objects.get(pk=zone)
			exhibitO=Exhibit.objects.get(pk=exhibit)
			nodeO.floor=floorO
			nodeO.zone=zoneO
			nodeO.exhibit=exhibitO
			nodeO.name=name
			nodeO.heartbeat_rate=heartbeat_rate
			nodeO.save()
			context['status']='Device Details Updated Successfully.'
			

			


	else:
		context['status']="You are not authorized for accessing other organization's Projects."

	return render(request,'museum/device_detail.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
def update_organization_detail(request):
	context={}
	return render(request,'museum/organization.html',context)

@login_required()
@user_passes_test(lambda u: u.is_staff)
def project(request):
	context={}
	if request.method=="POST" and 'create_project' in request.POST:
		project_name=request.POST.get('project_name')
		project_description=request.POST.get('project_description')
		projectO=Project.objects.create()
		projectO.name=project_name
		projectO.description=project_description
		projectO.save()
	elif request.method=="POST" and 'delete_project' in request.POST:
		project_pk=request.POST.get('project_pk')
	elif request.method=="POST" and 'edit_project' in request.POST:
		project_pk=request.POST.get('project_pk')
		project_name=request.POST.get('project_name')
		project_description=request.POST.get('project_description')



	return render(request,'museum/projects.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
def floor(request):
	context={}
	if request.method=='POST' and request.is_ajax() and 'unique_project_id' in request.POST:
		unique_project_id=request.POST.get('unique_project_id')
		unique_organization_id=request.POST.get('unique_organization_id')
		if Organization.objects.filter(pk=unique_organization_id).exists() and Project.objects.filter(pk=unique_project_id).exists():
			return redirect("/"+str(mms_userO.organization.id)+"/"+str(projO.id)+"/dashboard/")
		else:
			return JsonResponse({'message' : "Please select valid project details"})


	return render(request,'museum/floor.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
def zone(request):
	context={}
	return render(request,'museum/zone.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
def exhibit(request):
	context={}
	return render(request,'museum/exhibit.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
@module_is_entry_mms_user
def show(request,org_id,proj_id):
	context={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		showO=Show.objects.all()
		context['show']=showO
		if request.method=='POST' and request.is_ajax() and 'show_id_start' in request.POST:
			show_id=request.POST.get('show_id_start')
			showO=Show.objects.get(pk=show_id)
			showO.show_status=True
			showO.start_time=timezone.now()
			showO.save()
			show_detailO=ShowDetail.objects.filter(show=showO)
			for i in show_detailO:
				if Show.objects.get(pk=show_id).show_status==True:
					command_logO=CommandLog.objects.create()
					command_logO.command=i.command
					command_logO.node=i.node
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					if i.protocol=="TCP":
						tcp = TCPClient()
						tcp_response = tcp.sendTcpCommand(i.node.ip,i.node.port,i.command.name+' '+str(command_logO.pk))

						if tcp_response==True:
							command_log_batchO=CommandLogBatch.objects.create()
							command_log_batchO.command_log=command_logO
							command_log_batchO.status="SUCCESS"
							command_log_batchO.message="TCP Request sent successfully."
							command_log_batchO.updated_by=request.user
							command_log_batchO.save()

							# command_logO.status="SUCCESS"
							# command_logO.message="TCP Request sent successfully."
							# command_logO.save()
							
						else:
							command_log_batchO=CommandLogBatch.objects.create()
							command_log_batchO.command_log=command_logO
							command_log_batchO.status="FAILED"
							command_log_batchO.message=tcp_response
							command_log_batchO.updated_by=request.user
							command_log_batchO.save()
							# command_logO.status="FAILED"
							# command_logO.message=tcp_response
							# command_logO.save()

				else:
					break
			return JsonResponse({'status' : "Show Executed Successfully"})

		elif request.method=='POST' and request.is_ajax() and 'show_id_abort' in request.POST:
			show_id=request.POST.get('show_id_abort')
			show_language=request.POST.get('show_language')
			showO=Show.objects.get(pk=show_id)
			showO.show_status=False
			showO.save()
			show_detailO=ShowDetail.objects.filter(show=showO)
			if show_language == "english":
				commandO=Command.objects.get(name='resetE')
			else:
				commandO=Command.objects.get(name='resetH')
			for i in show_detailO:
				command_logO=CommandLog.objects.create()
				command_logO.command=commandO
				command_logO.node=i.node
				command_logO.created_by=request.user
				command_logO.updated_by=request.user
				command_logO.save()
				if i.protocol=="TCP":
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.node.ip,i.node.port,commandO.name+' '+str(command_logO.pk))

					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()
			return JsonResponse({'status' : "Show Terminated Successfully"})
		elif request.method=='POST' and request.is_ajax() and 'show_id_pause' in request.POST:
			show_id=request.POST.get('show_id_pause')
			showO=Show.objects.get(pk=show_id)
			showO.show_status=False
			showO.save()
			show_detailO=ShowDetail.objects.filter(show=showO)
			commandO=Command.objects.get(name='halt')
			for i in show_detailO:
				command_logO=CommandLog.objects.create()
				command_logO.command=commandO
				command_logO.node=i.node
				command_logO.created_by=request.user
				command_logO.updated_by=request.user
				command_logO.save()
				if i.protocol=="TCP":
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.node.ip,i.node.port,commandO.name+' '+str(command_logO.pk))

					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="FAILED"
						# command_logO.message=tcp_response
						# command_logO.save()
			return JsonResponse({'status' : "Show Paused Successfully"})

		elif request.method=='POST' and request.is_ajax() and 'show_id_play' in request.POST:
			show_id=request.POST.get('show_id_play')
			showO=Show.objects.get(pk=show_id)
			pause_time=showO.updated_at
			showO.show_status=True
			showO.save()
			show_detailO=ShowDetail.objects.filter(show=showO)
			timecount=0
			executed_show_time=(pause_time-showO.start_time).seconds
			for i in show_detailO:
				timecount=timecount+i.start_time
				# total_show_time=ShowDetail.objects.aggregate(Sum('start_time'))['start_time__sum']
				if Show.objects.get(pk=show_id).show_status==True:
					
					if executed_show_time < timecount:
						remaining_time_node=timecount-executed_show_time
						executed_show_time=executed_show_time+remaining_time_node
						command_logO=CommandLog.objects.create()
						command_logO.command=i.command
						command_logO.node=i.node
						command_logO.created_by=request.user
						command_logO.updated_by=request.user
						command_logO.save()
						if i.protocol=="TCP":
							tcp = TCPClient()
							tcp_response = tcp.sendTcpCommand(i.node.ip,i.node.port,i.command.name+' '+str(command_logO.pk))

							if tcp_response==True:
								command_log_batchO=CommandLogBatch.objects.create()
								command_log_batchO.command_log=command_logO
								command_log_batchO.status="SUCCESS"
								command_log_batchO.message="TCP Request sent successfully."
								command_log_batchO.updated_by=request.user
								command_log_batchO.save()

								# command_logO.status="SUCCESS"
								# command_logO.message="TCP Request sent successfully."
								# command_logO.save()
								
							else:
								command_log_batchO=CommandLogBatch.objects.create()
								command_log_batchO.command_log=command_logO
								command_log_batchO.status="FAILED"
								command_log_batchO.message=tcp_response
								command_log_batchO.updated_by=request.user
								command_log_batchO.save()
								# command_logO.status="FAILED"
								# command_logO.message=tcp_response
								# command_logO.save()
					else:
						pass

				else:
					break
			return JsonResponse({'status' : "Show Executed Successfully"})
		

	else:
		context['status']="You are not authorized for accessing other organization's Projects."
	return render(request,'museum/show.html',context)


class moderation_api(APIView):
	@csrf_exempt
	def post(self, request):
		data={}
		name=request.data.get("name")
		message=request.data.get("message")
		person_image=request.data.get("person_image")
		vision_image=request.data.get("vision_image")
		pledge_image=request.data.get("pledge_image")
		node_name=request.data.get("node_name")
		title=request.data.get("title")

		#print(vision_image)
		# person_image = base64.b64decode(person_image.encode('UTF-8'))
		# buf = io.BytesIO(person_image)
		#img = Image.open(buf)
		try:
			format, imgstr = person_image.split(';base64,') 
			ext = format.split('/')[-1] 
			person_image = ContentFile(base64.b64decode(imgstr), name='temp.' + ext)
			moderationO=Moderation.objects.create()
			moderationO.person_image=person_image
			moderationO.save()
			data['person_image']=moderationO.person_image.url
			data['id']=moderationO.pk
		except:
			return Response({"message": "Kindly Provide all the details."},status=HTTP_200_OK)
		if name!="" and name!=None:
			format, imgstr = name.split(';base64,') 
			ext = format.split('/')[-1] 
			name = ContentFile(base64.b64decode(imgstr), name='temp1.' + ext)
			moderationO.name=name
			moderationO.save()
			data['name']=moderationO.name.url
		if message != "" and message !=None:
			format, imgstr = message.split(';base64,') 
			ext = format.split('/')[-1] 
			message = ContentFile(base64.b64decode(imgstr), name='temp2.' + ext)
			moderationO.message=message
			moderationO.save()
			data['message']=moderationO.message.url
		if vision_image !="" and vision_image!=None:
			format, imgstr = vision_image.split(';base64,') 
			ext = format.split('/')[-1] 
			vision_image = ContentFile(base64.b64decode(imgstr), name='temp3.' + ext)
			moderationO.vision_image=vision_image
			moderationO.save()
			data['vision_image']=moderationO.vision_image.url
		if pledge_image != "" and pledge_image !=None:
			format, imgstr = pledge_image.split(';base64,') 
			ext = format.split('/')[-1] 
			pledge_image = ContentFile(base64.b64decode(imgstr), name='temp4.' + ext)
			moderationO.pledge_image=pledge_image
			moderationO.save()
			data['pledge_image']=moderationO.pledge_image.url
		if title != "" and title !=None:
			moderationO.title=title
			data['topic']=moderationO.title
			
		#change in the museum
		nodeO=Node.objects.get(name=node_name)
		#closed
		moderationO.node=nodeO
		moderationO.save()
		moderation_statusO=ModerationStatus.objects.get(pk=1)
		if moderation_statusO.is_moderate==True:
			userO=User.objects.get(username='mms')
			commandO=Command.objects.get(name="SHOW_ON_UI")
			command_logO=CommandLog.objects.create()
			command_logO.command=commandO
			command_logO.node=nodeO
			command_logO.created_by=userO
			command_logO.updated_by=userO
			command_logO.save()
			data = str(data).replace("'",'"')
			#print(data)
			sample_string_bytes = str(data).encode("ascii")
			base64_bytes = base64.b64encode(sample_string_bytes)
			base64_string = base64_bytes.decode("ascii")
			#print(base64_string)
			tcp = TCPClient()
			tcp_response = tcp.sendTcpCommand(nodeO.ip,nodeO.port,commandO.name+" "+str(command_logO.pk)+" "+base64_string)

			if tcp_response==True:
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="SUCCESS"
				command_log_batchO.message="TCP Request sent successfully."
				command_log_batchO.updated_by=userO
				command_log_batchO.save()
				# command_logO.status="SUCCESS"
				# command_logO.message="TCP Request sent successfully."
				# command_logO.save()
				
			else:
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="FAILED"
				command_log_batchO.message=tcp_response
				command_log_batchO.updated_by=userO
				command_log_batchO.save()
		else:
			pass
		return Response({"message": "Moderation added Successfully."},status=HTTP_200_OK)

@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
@module_is_entry_mms_user
def show_on_ui(request,org_id,proj_id):
	context={}
	kwargs={}
	data=[]
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		if request.method=='GET' and request.is_ajax():
			if 'node_name' in request.GET:
				node_name=request.GET.get('node_name')
				if node_name!="" and node_name!=None:
					nodeO=Node.objects.get(name=node_name)
					kwargs['{0}'.format('node')]= nodeO
			page_number = request.GET.get('page')
			moderationO=Moderation.objects.filter(**kwargs).order_by('-id')
			paginator = Paginator(moderationO, 25) # Show 50 moderations
			page_obj = paginator.get_page(page_number)
			for i in page_obj:
				data.append({"id" : i.pk,"name":i.name.url,"message" : i.message.url,"person_image" : i.person_image.url, 'num_pages' : paginator.num_pages})
			return JsonResponse({'data' : data})
#		if 'node_name' in request.GET:
#			node_name=request.GET.get('node_name')
#			nodeO=Node.objects.get(name=node_name)
#			kwargs['{0}'.format('node')]= node_name
#		page_number = request.GET.get('page')
#		moderationO=Moderation.objects.filter(**kwargs).order_by('-id')
#		paginator = Paginator(moderationO, 25) # Show 50 moderations
#		page_obj = paginator.get_page(page_number)
#		context['moderation']=page_obj
		if request.method=='POST' and request.is_ajax() and 'show_id_start' in request.POST:
			#userO=User.objects.get(username='mms')
			moderation_id=request.POST.get('show_id_start')
			single_moderationO=Moderation.objects.get(pk=moderation_id)
			commandO=Command.objects.get(name="SHOW_ON_UI")
			command_logO=CommandLog.objects.create()
			command_logO.command=commandO
			command_logO.node=single_moderationO.node
			command_logO.created_by=request.user
			command_logO.updated_by=request.user
			command_logO.save()
			data={"name" : single_moderationO.name.url, "message" : single_moderationO.message.url, "person_image" : single_moderationO.person_image.url}
			data = str(data).replace("'",'"')
			sample_string_bytes = str(data).encode("ascii")
			base64_bytes = base64.b64encode(sample_string_bytes)
			base64_string = base64_bytes.decode("ascii")
			#print(base64_string)
			
			tcp = TCPClient()
			tcp_response = tcp.sendTcpCommand(single_moderationO.node.ip,single_moderationO.node.port,commandO.name+" "+str(command_logO.pk)+" "+base64_string)

			if tcp_response==True:
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="SUCCESS"
				command_log_batchO.message="TCP Request sent successfully."
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()
				# command_logO.status="SUCCESS"
				# command_logO.message="TCP Request sent successfully."
				# command_logO.save()
				
			else:
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="FAILED"
				command_log_batchO.message=tcp_response
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()
			return JsonResponse({'status' : "Show on UI Executed Successfully"})

		
	else:
		context['status']="You are not authorized for accessing other organization's Projects."
	return render(request,'museum/moderation.html',context)


@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
@module_is_entry_mms_user
def delete_from_ui(request,org_id,proj_id):
	context={}
	kwargs={}
	data=[]
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
#		if 'node_name' in request.GET:
#			node_name=request.GET.get('node_name')
#			nodeO=Node.objects.get(name=node_name)
#			kwargs['{0}'.format('node')]= node_name
#		page_number = request.GET.get('page')
#		moderationO=Moderation.objects.filter(**kwargs).order_by('-id')
#		paginator = Paginator(moderationO, 25) # Show 50 moderations
#		page_obj = paginator.get_page(page_number)
#		context['moderation']=page_obj
		if request.method=='GET' and request.is_ajax():
			if 'node_name' in request.GET:
				node_name=request.GET.get('node_name')
				if node_name!="" and node_name!=None:
					nodeO=Node.objects.get(name=node_name)
					kwargs['{0}'.format('node')]= nodeO
			page_number = request.GET.get('page')
			moderationO=Moderation.objects.filter(**kwargs).order_by('-id')
			paginator = Paginator(moderationO, 25) # Show 50 moderations
			page_obj = paginator.get_page(page_number)
			for i in page_obj:
				data.append({"id" : i.pk,"name":i.name.url,"message" : i.message.url,"person_image" : i.person_image.url, 'num_pages' : paginator.num_pages})
			return JsonResponse({'data' : data})
		if request.method=='POST' and request.is_ajax() and 'show_id_start' in request.POST:
			#userO=User.objects.get(username='mms')
			moderation_id=request.POST.get('show_id_start')
			single_moderationO=Moderation.objects.get(pk=moderation_id)
			commandO=Command.objects.get(name="DELETE_FROM_UI")
			command_logO=CommandLog.objects.create()
			command_logO.command=commandO
			command_logO.node=single_moderationO.node
			command_logO.created_by=request.user
			command_logO.updated_by=request.user
			command_logO.save()
			tcp = TCPClient()
			tcp_response = tcp.sendTcpCommand(single_moderationO.node.ip,single_moderationO.node.port,commandO.name+" "+str(command_logO.pk)+" "+str(single_moderationO.pk))

			if tcp_response==True:
				single_moderationO.delete()
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="SUCCESS"
				command_log_batchO.message="TCP Request sent successfully."
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()
				# command_logO.status="SUCCESS"
				# command_logO.message="TCP Request sent successfully."
				# command_logO.save()
				
			else:
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="FAILED"
				command_log_batchO.message=tcp_response
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()
			return JsonResponse({'status' : "Delete From UI done Successfully"})

		
	else:
		context['status']="You are not authorized for accessing other organization's Projects."
	return render(request,'museum/delete_moderation.html',context)
		




class latest_moderation_api(APIView):
	def get(self, request):
		data=[]
		node_name=request.GET.get("node_name")
		#print(node_name)
		nodeO=Node.objects.get(name=node_name)
		moderationO=Moderation.objects.filter(node=nodeO).order_by('-id')[0:10]
		for i in moderationO:
			context={}
			if i.pk:
				context['id']=i.pk
			if i.name:
				context['name']=i.name.url
			if i.message:
				context['message']=i.message.url
			if i.person_image:
				context['person_image']=i.person_image.url
			if i.vision_image:
				context['vision_image']=i.vision_image.url
			if i.pledge_image:
				context['pledge_image']=i.pledge_image.url
			if i.title:
				context['topic']=i.title
			data.append(context)

		return Response({"data": data},status=HTTP_200_OK)


class pm_selection_api(APIView):
	def post(self, request):
		data=[]
		pm_no=request.POST.get("pm_no")
		category=request.POST.get("category")
		print(pm_no,category)

		pm_name=["SHRI JAWAHARLAL NEHRU", "SHRI GULZARILAL NANDA","SHRI LAL BAHADUR SHASTRI", "SMT. INDIRA GANDHI","SHRI MORARJI DESAI","SHRI CHARAN SINGH","SHRI RAJIV GANDHI", "SHRI VISHWANATH PRATAP SINGH","SHRI CHANDRA SHEKHAR","SHRI P.V. NARASIMHA RAO","SHRI H.D DEVE GOWDA","SHRI INDER KUMAR GUJRAL","SHRI ATAL BIHARI VAJPAYEE","DR. MANMOHAN SINGH","SHRI NARENDRA MODI"]
		if pm_no and category:
			pm_selectionO=PMSelection.objects.create()
			pm_selectionO.pm_name=pm_name[int(pm_no)]
			pm_selectionO.category=category
			pm_selectionO.save()
			return Response({"Success": "Pm Count increased Successfully."},status=HTTP_200_OK)
		else:
			return Response({"Failure": "Kindly Provide the details Carefully"},status=HTTP_200_OK)


def logout_view(request):
	context={}
	logout(request)
	return redirect("/")

	
@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
def Projectors(request,org_id,proj_id):
	context={}
	command_list=[]
	kwargs={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	if projectO.organization==organizationO:
		command_offO=Command.objects.get(name="shutdown")
		command_onO=Command.objects.get(name="TurnOn")
		context['command_off']=command_offO
		context['command_on']=command_onO
		floorO=Floor.objects.filter(project=projectO).order_by('name')
		context['floor']=floorO
		zoneO=Zone.objects.filter(project=projectO).order_by('name')
		context['zone']=zoneO
		exhibitO=Exhibit.objects.filter(project=projectO).order_by('name')
		context['exhibit']=exhibitO
		if request.method=='GET' and request.is_ajax():
			data=[]
			kwargs['{0}'.format('project')]= projectO
			kwargs['{0}__{1}'.format('category','in')]= ["PROJECTOR", "PROJECTOR_B15"]

			if 'floor_id[]' in request.GET:
				floor_id=request.GET.getlist('floor_id[]')
				kwargs['{0}__{1}__{2}'.format('floor', 'pk', 'in')]= floor_id

			if 'zone_id[]' in request.GET:
				zone_id=request.GET.getlist('zone_id[]')
				kwargs['{0}__{1}__{2}'.format('zone', 'pk', 'in')]= zone_id

			if 'exhibit_id[]' in request.GET:
				exhibit_id=request.GET.getlist('exhibit_id[]')
				kwargs['{0}__{1}__{2}'.format('exhibit', 'pk', 'in')]= exhibit_id
			
			
			nodeO=Node.objects.filter(**kwargs)
			

			for i in nodeO:
				data.append({'id' : i.pk, 'name' : i.name, 'ip' : i.ip, 'floor' : i.floor.name, 'zone' : i.zone.name, 'exhibit' : i.exhibit.name}) 

			return JsonResponse({'data': data, 'command' : [{'id' : command_offO.pk, 'name' : command_offO.name},{'id' : command_onO.pk, 'name' : command_onO.name}]}) 

		elif request.method=="POST" and request.is_ajax() and "command_id" in request.POST:
			#print(request.POST)
			node_id=request.POST.getlist('node_id[]')
			command_id=request.POST.get('command_id')
			#print(node_id)
			#print(command_id)
			commandO=Command.objects.get(pk=command_id)
			if Node.objects.filter(pk__in=node_id).exists():
				nodeO=Node.objects.filter(pk__in=node_id)
				for i in nodeO:
					if i.category =="PROJECTOR":
						command_logO=CommandLog.objects.create()
						command_logO.command=commandO
						command_logO.node=i
						command_logO.created_by=request.user
						command_logO.updated_by=request.user
						command_logO.save()
						tcp = TCPClient()
						if commandO.name=="TurnOn":
							tcp_response = tcp.sendTcpCommand(i.ip,i.port,"%1POWR 1\r")
						else:
							tcp_response = tcp.sendTcpCommand(i.ip,i.port,"%1POWR 0\r")

						if tcp_response==True:
							command_log_batchO=CommandLogBatch.objects.create()
							command_log_batchO.command_log=command_logO
							command_log_batchO.status="SUCCESS"
							command_log_batchO.message="TCP Request sent successfully."
							command_log_batchO.updated_by=request.user
							command_log_batchO.save()
							# command_logO.status="SUCCESS"
							# command_logO.message="TCP Request sent successfully."
							# command_logO.save()
						
						else:
							command_log_batchO=CommandLogBatch.objects.create()
							command_log_batchO.command_log=command_logO
							command_log_batchO.status="FAILED"
							command_log_batchO.message=tcp_response
							command_log_batchO.updated_by=request.user
							command_log_batchO.save()
							# command_logO.status="FAILED"
							# command_logO.message=tcp_response
							# command_logO.save()
				return JsonResponse({'status':"Command Logs has been created. Go to Command Logs for more details."})
					
			else:
				return JsonResponse({'status':"Please Select the node to send the commands"})

	else:
		context['status']="You are not authorized for accessing other organization's Projects."


	return render(request,'museum/projectors.html',context)


class backup_mms_api(APIView):
	#permission_classes = (IsAuthenticated,)
	def get(self, request):
		data=[]
		ig_ips=[]
		gr_ips=[]
		nodeO=Node.objects.filter(is_control_panel=True,is_config=True).order_by('sequence_id')
		show_igO=Show.objects.get(name="IG TUNNEL")
		show_grO=Show.objects.get(name="Green Revolution")
		show_detail_igO=ShowDetail.objects.filter(show=show_igO)
		show_detail_grO=ShowDetail.objects.filter(show=show_grO)
		for i in nodeO:
			watchout_videos=[]
			if i.category == "WATCHOUT":
				watchout_videosO=WatchoutVideo.objects.filter(node=i)
				for j in watchout_videosO:
					watchout_videos.append({"name" : j.video_name,"video_duration" : j.video_duration})
				data.append({'name' : i.name, 'ip' : i.ip, 'floor' : i.floor.name, 'zone' : i.zone.name, 'exhibit' : i.exhibit.name, 'current_video_status' : i.current_video_status,'category' : i.category, "watchout_videos" : watchout_videos})
			else:
				data.append({'name' : i.name, 'ip' : i.ip, 'floor' : i.floor.name, 'zone' : i.zone.name, 'exhibit' : i.exhibit.name, 'current_video_status' : i.current_video_status,'category' : i.category})
		for j in show_detail_igO:
			ig_ips.append(j.node.ip)
		for j in show_detail_grO:
			gr_ips.append(j.node.ip)
		return Response({"data": data,"show" : [{"name" : "IG TUNNEL", "ip" : ig_ips},{"name" : "Green Revolution", "ip" : gr_ips}]},status=HTTP_200_OK)


#class audio_guide_api(APIView):
	#permission_classes = (IsAuthenticated,)
#	def get(self, request):

#		data=[]
#		f = open('../media/updatedJson2.json')
#		data=json.loads(f)
		
#		return Response({"data": data,"show" : [{"name" : "IG TUNNEL", "ip" : ig_ips},{"name" : "Green Revolution", "ip" : gr_ips}]},status=HTTP_200_OK)


@login_required()
@user_passes_test(lambda u: u.is_staff)
@csrf_exempt
@module_is_entry_mms_user
def museum_on_off(request,org_id,proj_id):
	context={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		floorO=Floor.objects.all()
		context['floor']=floorO
		if request.method=='POST' and "shutdown_floor_id" in request.POST:
			floor_id=request.POST.get('shutdown_floor_id')
			floorO=Floor.objects.get(pk=floor_id)
			nodeO=Node.objects.filter(floor=floorO).exclude(category__in=["PROJECTOR","PROJECTOR_B15"])
			commandO=Command.objects.get(name="shutdown")
			for i in nodeO:
				if device_status_check(i.pk) =="online":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,commandO.name+' '+str(command_logO.pk))

					if tcp_response==True:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="SUCCESS"
						command_log_batchO.message="TCP Request sent successfully."
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
						# command_logO.status="SUCCESS"
						# command_logO.message="TCP Request sent successfully."
						# command_logO.save()
						
					else:
						command_log_batchO=CommandLogBatch.objects.create()
						command_log_batchO.command_log=command_logO
						command_log_batchO.status="FAILED"
						command_log_batchO.message=tcp_response
						command_log_batchO.updated_by=request.user
						command_log_batchO.save()
			context[status]= floorO.name+"\'s Servers Shut Down Successfully.Go to Command Logs for more details."

		elif request.method=='POST' and "TurnOn_floor_id" in request.POST:
			floor_id=request.POST.get('TurnOn_floor_id')
			floorO=Floor.objects.get(pk=floor_id)
			nodeO=Node.objects.filter(floor=floorO).exclude(category__in=["PROJECTOR","PROJECTOR_B15"])
			commandO=Command.objects.get(name="TurnOn")
			for i in nodeO:
				command_logO=CommandLog.objects.create()
				command_logO.command=commandO
				command_logO.node=i
				command_logO.created_by=request.user
				command_logO.updated_by=request.user
				command_logO.save()
				send_magic_packet(i.mac_addr)
				command_log_batchO=CommandLogBatch.objects.create()
				command_log_batchO.command_log=command_logO
				command_log_batchO.status="SUCCESS"
				command_log_batchO.message="TurnOn Command sent successfully"
				command_log_batchO.updated_by=request.user
				command_log_batchO.save()

		
			context[status]= floorO.name+"\'s Servers Turn On Successfully.Go to Command Logs for more details."
		elif request.method=='POST' and "shutdown_projectors" in request.POST:
			commandO=Command.objects.get(name="shutdown")
			nodeO=Node.objects.filter(category__in=["PROJECTOR","PROJECTOR_B15"])
			for i in nodeO:
				if i.category =="PROJECTOR":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,"%1POWR 0\r")
					if tcp_response==True:
							command_log_batchO=CommandLogBatch.objects.create()
							command_log_batchO.command_log=command_logO
							command_log_batchO.status="SUCCESS"
							command_log_batchO.message="TCP Request sent successfully."
							command_log_batchO.updated_by=request.user
							command_log_batchO.save()
							# command_logO.status="SUCCESS"
							# command_logO.message="TCP Request sent successfully."
							# command_logO.save()

					else:
							command_log_batchO=CommandLogBatch.objects.create()
							command_log_batchO.command_log=command_logO
							command_log_batchO.status="FAILED"
							command_log_batchO.message=tcp_response
							command_log_batchO.updated_by=request.user
							command_log_batchO.save()
							# command_logO.status="FAILED"
							# command_logO.message=tcp_response
							# command_logO.save()
				else:
					#needs to implement for ig projector
					pass
			context[status]= "Projectors Shut Down Successfully.Go to Command Logs for more details."
		elif request.method=='POST' and "TurnOn_projectors" in request.POST:
			commandO=Command.objects.get(name="TurnOn")
			nodeO=Node.objects.filter(category__in=["PROJECTOR","PROJECTOR_B15"])
			for i in nodeO:
				if i.category =="PROJECTOR":
					command_logO=CommandLog.objects.create()
					command_logO.command=commandO
					command_logO.node=i
					command_logO.created_by=request.user
					command_logO.updated_by=request.user
					command_logO.save()
					tcp = TCPClient()
					tcp_response = tcp.sendTcpCommand(i.ip,i.port,"%1POWR 1\r")
					if tcp_response==True:
							command_log_batchO=CommandLogBatch.objects.create()
							command_log_batchO.command_log=command_logO
							command_log_batchO.status="SUCCESS"
							command_log_batchO.message="TCP Request sent successfully."
							command_log_batchO.updated_by=request.user
							command_log_batchO.save()
							# command_logO.status="SUCCESS"
							# command_logO.message="TCP Request sent successfully."
							# command_logO.save()

					else:
							command_log_batchO=CommandLogBatch.objects.create()
							command_log_batchO.command_log=command_logO
							command_log_batchO.status="FAILED"
							command_log_batchO.message=tcp_response
							command_log_batchO.updated_by=request.user
							command_log_batchO.save()
				else:
					#needs to implement for ig projector
					pass
			context[status]= "Projectors Turn On Successfully.Go to Command Logs for more details."


	else:
		context['status']="You are not authorized for accessing other organization's Projects."
	return render(request,'museum/museum_on_off.html',context)



def change_password(request,org_id,proj_id):
	context={}
	organizationO=Organization.objects.get(pk=org_id)
	projectO=Project.objects.get(pk=proj_id)
	context['org']=organizationO
	context['proj']=projectO
	mms_userO=MMSUser.objects.get(user=request.user)
	context['mms_user']=mms_userO
	if projectO.organization==organizationO:
		u=User.objects.get(username=request.user.username)
		if request.method=='POST':
			old_password=request.POST.get('old_password')
			new_password=request.POST.get('new_password')
			confirm_new_password=request.POST.get('confirm_new_password')
			if new_password == confirm_new_password:
				if check_password(old_password, u.password):
					u.set_password(new_password)
					u.save()
					update_session_auth_hash(request,u)
					context['status_success']='Password changed successfully.'
				else:
					context['status_danger']='Please enter correct old password.'
			else:
				context['status_warning']='New Password and Confirm New Password are not same.'
		
	return render(request,"museum/change_password.html",context)