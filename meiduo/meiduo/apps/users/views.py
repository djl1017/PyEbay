import random

import logging
import re

from django.http import HttpResponse
from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.generics import CreateAPIView, ListAPIView, GenericAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import RetrieveAPIView, UpdateAPIView
from rest_framework.viewsets import GenericViewSet
from rest_framework.mixins import CreateModelMixin, UpdateModelMixin
from django_redis import get_redis_connection
from rest_framework_jwt.views import ObtainJSONWebToken

from oauth.utils import generate_save_user_token, check_save_user_token
from .serializers import UserSerializer, UserDetailSerializer, EmailSerializer, UserAddressSerializer, \
    AddressTitleSerializer, UserBrowseHistorySerializer, UserUpdatePasswordSerializer, UserCountForGetpswdSerializer

from .models import User, Address
from goods.models import SKU
from goods.serializers import SKUSerializer
from carts.utils import merge_cart_cookie_to_redis
from celery_tasks.sms.tasks import send_sms_code

logger = logging.getLogger('django')  # 创建日志输出器


# 修改页面
# POST /users/undefined/password/
class ForGetupdate(APIView):
    def post(self, request, userid):

        user = User.objects.get(id=userid)
        # password = request.POST.get('password')
        password = request.data.get('password')
        password2 = request.data.get('password2')
        print(password, password2)
        if password != password2:
            return Response({'message': '两次不一致'}, status=status.HTTP_400_BAD_REQUEST)

        if not re.match(r'\S{8,20}', password):
            return Response({'message': '密码格式不正确'}, status=status.HTTP_400_BAD_REQUEST)

        redis_conn = get_redis_connection('verify_codes')
        try:
            is_access = redis_conn.get('access_%s' % user.username)

        except:
            return Response({'message': '无效用户'}, status=status.HTTP_400_BAD_REQUEST)

        if not is_access:
            return Response({'message': '超时'}, status=status.HTTP_400_BAD_REQUEST)

        # 删除该值
        redis_conn.delete('access_%s' % user.username)

        user.set_password(password)
        user.save()

        print('保存%s密码成功' % userid)
        return Response({'message': 'OK'})


class UserUpdatePasswordView(UpdateAPIView):
    permission_classes = [IsAuthenticated]

    serializer_class = UserUpdatePasswordSerializer


# Create your views here


# # 验证忘记手机验证码
# GET /accounts/fklucky/password/token/?sms_code=511058
class ForGetPswd_sms_code(APIView):
    """验证手机验证码模块"""

    def get(self, request, username):

        sms_code = request.GET.get('sms_code')

        use = User.objects.get(username=username)

        mobile = use.mobile

        if not sms_code:
            return Response({'message': '错误请求'}, status=status.HTTP_400_BAD_REQUEST)
        redis_conn = get_redis_connection('verify_codes')

        real_code = redis_conn.get('fgt_sms_%s' % mobile).decode()

        if real_code != sms_code:
            return Response({'message': '验证码错误'}, status=status.HTTP_400_BAD_REQUEST)

        # 删除该值
        redis_conn.delete('fgt_sms_%s' % mobile)

        # 添加标记
        redis_conn = get_redis_connection('verify_codes')
        redis_conn.setex('access_%s' % use.username, 300, 300)

        return Response({'message': 'OK', 'user_id': use.id})


# 手机发送验证码模块
# GET /sms_codes/?access_token=eyJleHAiOjE1NT
class ForGetPswd(APIView):
    """发送手机验证码"""

    def get(self, request):
        access_teken = request.GET.get('access_token')
        mobile = check_save_user_token(access_teken)

        redis_conn = get_redis_connection('verify_codes')

        flag = redis_conn.get('send_flag_%s' % mobile)

        if flag:  # 如果if成立说明此手机号60秒内发过短信
            return Response({'message': '频繁发送短信'}, status=status.HTTP_400_BAD_REQUEST)

        sms_code = '%06d' % random.randint(0, 999999)
        logger.info(sms_code)

        pl = redis_conn.pipeline()

        pl.setex('fgt_sms_%s' % mobile, 300, sms_code)

        pl.setex('fgt_send_flag_%s' % mobile, 60, 1)

        pl.execute()

        send_sms_code.delay(mobile, sms_code)
        return Response({'message': 'ok'})


# url(r'^accounts/(?P<username>\w{5,20})/sms/$', views.UsernameCountView.as_view()),
class ForGetUsernameCountView(APIView):
    """验证用户名是否已存在"""

    def get(self, request, username):
        request_dict = request.GET
        image_code_id = request_dict.get('image_code_id')
        text = request_dict.get('text')

        """使用序列化器"""
        serializer = UserCountForGetpswdSerializer(data={
            'image_code_id': image_code_id,
            'text': text,
            'username': username})
        serializer.is_valid(raise_exception=True)

        print(serializer.validated_data)
        return Response(serializer.validated_data)


class UserAuthorizeView(ObtainJSONWebToken):
    """重写账号密码登录视图"""

    def post(self, request, *args, **kwargs):
        response = super(UserAuthorizeView, self).post(request, *args, **kwargs)
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user = serializer.object.get('user') or request.user
            merge_cart_cookie_to_redis(request, user, response)

        return response


# POST/GET  /browse_histories/
class UserBrowseHistoryView(CreateAPIView):
    """用户浏览记录"""

    # 指定序列化器(校验)
    serializer_class = UserBrowseHistorySerializer
    # 指定权限
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """读取用户浏览记录"""
        # 创建redis连接对象
        redis_conn = get_redis_connection('history')
        # 查询出redis中当前登录用户的浏览记录[b'1', b'2', b'3']
        sku_ids = redis_conn.lrange('history_%d' % request.user.id, 0, -1)

        # 把sku_id对应的sku模型取出来
        # skus = SKU.objects.filter(id__in=sku_ids)  # 此查询它会对数据进行排序处理
        # 查询sku列表数据
        sku_list = []
        for sku_id in sku_ids:
            sku = SKU.objects.get(id=sku_id)
            sku_list.append(sku)

        # 序列化器
        serializer = SKUSerializer(sku_list, many=True)

        return Response(serializer.data)


class AddressViewSet(UpdateModelMixin, CreateModelMixin, GenericViewSet):
    """用户收货地址"""
    permission_classes = [IsAuthenticated]

    serializer_class = UserAddressSerializer

    def create(self, request, *args, **kwargs):
        """新增收货地址"""
        # 判断用户的收货地址数量是否上限
        # address_count = Address.objects.filter(user=request.user).count()
        address_count = request.user.addresses.count()
        if address_count > 20:
            return Response({'message': '收货地址数量上限'}, status=status.HTTP_400_BAD_REQUEST)
        # # 创建序列化器给data参数传值(反序列化)
        #         # serializer = UserAddressSerializer(data=request.data, context={'request': request})
        #         # # 调用序列化器的is_valid方法
        #         # serializer.is_valid(raise_exception=True)
        #         # # 调用序列化器的save
        #         # serializer.save()
        #         # # 响应
        #         # return Response(serializer.data, status=status.HTTP_201_CREATED)
        return super(AddressViewSet, self).create(request, *args, **kwargs)

    def get_queryset(self):
        return self.request.user.addresses.filter(is_deleted=False)

    # GET /addresses/
    def list(self, request, *args, **kwargs):
        """
        用户地址列表数据
        """
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        user = self.request.user
        return Response({
            'user_id': user.id,
            'default_address_id': user.default_address_id,
            'limit': 20,
            'addresses': serializer.data
        })

    def destroy(self, request, *args, **kwargs):
        """
        处理删除
        """
        address = self.get_object()

        # 进行逻辑删除
        address.is_deleted = True
        address.save()

        return Response(status=status.HTTP_204_NO_CONTENT)

    # put /addresses/pk/status/
    @action(methods=['put'], detail=True)
    def status(self, request, pk=None):
        """
        设置默认地址
        """
        address = self.get_object()
        request.user.default_address = address
        request.user.save()
        return Response({'message': 'OK'}, status=status.HTTP_200_OK)

    # put /addresses/pk/title/
    # 需要请求体参数 title
    @action(methods=['put'], detail=True)
    def title(self, request, pk=None):
        """
        修改标题
        """
        address = self.get_object()
        serializer = AddressTitleSerializer(instance=address, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class EmailVerifyView(APIView):
    """激活邮箱"""

    def get(self, request):

        # 1.获取前token查询参数
        token = request.query_params.get('token')
        if not token:
            return Response({'message': '缺少token'}, status=status.HTTP_400_BAD_REQUEST)

        # 对token解密并返回查询到的user
        user = User.check_verify_email_token(token)

        if not user:
            return Response({'message': '无效token'}, status=status.HTTP_400_BAD_REQUEST)

        # 修改user的email_active字段
        user.email_active = True
        user.save()

        return Response({'message': 'ok'})


# PUT  /email/
class EmailView(UpdateAPIView):
    """保存邮箱"""
    permission_classes = [IsAuthenticated]
    # 指定序列化器
    serializer_class = EmailSerializer

    def get_object(self):
        return self.request.user


"""
# GET   /user/
class UserDetailView(APIView):
    # 提供用户个人信息接口
    # 指定权限,必须是通过认证的用户才能访问此接口(就是当前本网站的登录用户)
    permission_classes = [IsAuthenticated] 

    def get(self, request):
        user = request.user  # 获取本次请求的用户对象
        serializer = UserDetailSerializer(user)
        return Response(serializer.data)
"""


class UserDetailView(RetrieveAPIView):
    """提供用户个人信息接口"""
    permission_classes = [IsAuthenticated]  # 指定权限,必须是通过认证的用户才能访问此接口(就是当前本网站的登录用户)

    serializer_class = UserDetailSerializer  # 指定序列化器

    # queryset = User.objects.all()
    def get_object(self):  # 返回指定模型对象
        return self.request.user


# POST /users/
class UserView(CreateAPIView):
    """用户注册"""
    # 指定序列化器
    serializer_class = UserSerializer


# url(r'^usernames/(?P<username>\w{5,20})/count/$', views.UsernameCountView.as_view()),
class UsernameCountView(APIView):
    """验证用户名是否已存在"""

    def get(self, request, username):
        # 查询用户名是否已存在
        count = User.objects.filter(username=username).count()

        # 构建响应数据
        data = {
            'count': count,
            'username': username
        }
        return Response(data)


# url(r'^mobiles/(?P<mobile>1[3-9]\d{9})/count/$', views.MobileCountView.as_view()),
class MobileCountView(APIView):
    """验证手机号是否已存在"""

    def get(self, request, mobile):
        # 查询手机号数量
        count = User.objects.filter(mobile=mobile).count()

        data = {
            'count': count,
            'mobile': mobile
        }
        return Response(data)
