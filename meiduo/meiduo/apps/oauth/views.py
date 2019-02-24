from rest_framework.views import APIView
from QQLoginTool.QQtool import OAuthQQ
from rest_framework.response import Response
from rest_framework import status
import logging
from rest_framework_jwt.settings import api_settings
from django_redis import get_redis_connection
from django.conf import settings
from django.http import HttpResponse
import random

from .models import QQAuthUser, OAuthSinaUser
from .utils import generate_save_user_token, check_save_user_token
from .serializers import QQAuthUserSerializer, WeiboAuthUserSerializer
from carts.utils import merge_cart_cookie_to_redis
from .utils import WeiboSDK
from meiduo.libs.captcha.captcha import captcha
from . import constants
from celery_tasks.sms.tasks import send_sms_code

logger = logging.getLogger('django')

class WeiboRegisterView(APIView):
    def post(self, request):
        pass

class GenerateSmsCodeView(APIView):
    """生成短信验证码视图"""

    def get(self, request, mobile):
        """
        1.获取uuid　和　用户输入的image_code
        2.校验用户输入的image_code  和　redis中实际存储的real_image_code是否一致
        3.校验用户该mobile是否频繁发送短信验证码
        4.校验成功将redis中数据清除。
        5.生成随机短信验证码，使用celery异步发送短信，redis中存储该手机的real_sms_code
        :param request:
        :param mobile:
        :return:
        """
        query_dict = request.query_params
        image_code = query_dict.get('text')
        uuid = query_dict.get('image_code_id')
        logger.info('image_code:' + image_code)
        logger.info('uuid:' + uuid)

        if not all([image_code, uuid]):
            return Response({'message': '参数不全'}, status=status.HTTP_400_BAD_REQUEST)

        redis_conn = get_redis_connection('verify_codes')

        real_image_code = redis_conn.get('ImageCode_' + uuid)

        if not real_image_code:
            return Response({'message': '短信验证码过期'}, status=status.HTTP_400_BAD_REQUEST)

        real_image_code = real_image_code.decode()
        redis_conn.delete('ImageCode_' + uuid)


        logger.info('image_code:' + image_code)
        logger.info('real_image_code:' + real_image_code)
        if image_code.lower() != real_image_code.lower():
            logger.error('图片验证码错误')
            return Response({'message': '图片验证码错误'}, status=status.HTTP_400_BAD_REQUEST)

        send_flag = redis_conn.get('send_flag_%s' % mobile)
        if send_flag:
            logger.error('频繁发送短信')
            return Response({'message': '频繁发送短信'}, status=status.HTTP_400_BAD_REQUEST)

        sms_code = '%06d' % random.randint(0, 999999)
        logger.info('sms_code%s' % sms_code)

        pl = redis_conn.pipeline()
        pl.setex('sms_code_%s' % mobile, constants.SMS_CODE_REDIS_EXPIRES, sms_code)
        pl.setex('flag_%s' % mobile, constants.SEND_SMS_CODE_INTERVAL, 1)
        pl.execute()
        send_sms_code.delay(mobile, sms_code)

        return Response({'message': '发送短信成功'})


class GenerateImgCodeView(APIView):
    """生成图片验证码视图"""

    def get(self, request, code_id):
        """
        1.获取前端生成的code_id
        2.使用captcha，生成图片验证码
        3.redis中保存数据
        4.返回图片验证码
        """
        name, text, image = captcha.generate_captcha()
        redis_conn = get_redis_connection('verify_codes')

        try:
            # 保存当前生成的图片验证码内容
            redis_conn.setex('ImageCode_' + code_id, settings.IMAGE_CODE_REDIS_EXPIRES, text)
        except Exception as e:
            logger.error(e)
            return Response({'message': '保存图片验证码失败'}, status=status.HTTP_400_BAD_REQUEST)

        return HttpResponse(image, content_type='image/jpg')


class WeiboAuthURLView(APIView):
    """提供微博登录页面网址"""

    def get(self, request):
        "生成微博登录链接"
        # 获取next(从哪去取到login)参数路基
        next = request.query_params.get('next')
        if not next:
            next = '/'

        authoweibo = WeiboSDK(
            client_id=settings.SINA_CLIENT_ID,
            client_secret=settings.SINA_CLIENT_SECRET,
            redirect_uri=settings.SINA_REDIRECT_URI,
            state = next,

        )

        # 拼接好的登录链接
        login_url = authoweibo.get_weibo_login_url()

        return Response({'login_url': login_url})


class WeiboAuthUserView(APIView):
    "登录成功后回调处理"

    def get(self, request):
        # 获取查询参数中的code 参数
        code = request.query_params.get('code')
        if not code:
            return Response({'message': "没有code"})

        authoweibo = WeiboSDK(
            client_id=settings.SINA_CLIENT_ID,
            client_secret=settings.SINA_CLIENT_SECRET,
            redirect_uri=settings.SINA_REDIRECT_URI,
        )

        # 通过code作为获取 access_token的url的参数
        try:
            access_token = authoweibo.get_access_token(code)
        except:
            return Response({'message': '微博服务器异常'})

        logger.info('access_token' + access_token)

        try:
            # 查询weibo_token 是否绑定过商城中的用户

            weibo_auth_model = OAuthSinaUser.objects.get(access_token=access_token)
        except OAuthSinaUser.DoesNotExist:
            # 视图一定要有返回值, 之前写的是pass, 就一直没有处理了

            # 将access_token加密后返回给前端, 保存一下
            access_token = generate_save_user_token(access_token)
            return Response({'access_token': access_token})

        else:  # 已经绑定过, 则手动生成token
            jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER  # 加载生成载荷函数
            jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER  # 加载生成token函数

            # 获取user对象
            user = weibo_auth_model.user
            payload = jwt_payload_handler(user)  # 生成载荷
            token = jwt_encode_handler(payload)  # 根据载荷生成token

            logger.info('token:' + token)

            response = Response({
                'token': token,
                'username': user.username,
                'user_id': user.id
            })

            # cookie购物车合并到redis
            # merge_cart_cookie_to_redis(request, user, response)
            return response

    def post(self, request):
        """登录post"""

        # 创建序列化器, 进行反序列化
        serializer = WeiboAuthUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # 手动生成jwt token
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER  # 加载生成载荷函数
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER  # 加载生成token函数

        payload = jwt_payload_handler(user)  # 生成载荷
        token = jwt_encode_handler(payload)  # 根据载荷生成token

        return Response({
            'token': token,
            'username': user.username,
            'user_id': user.id
        })


class QQAuthUserView(APIView):
    """扫码成功后回调处理"""

    def get(self, request):
        # 1.获取查询参数中的code参数
        code = request.query_params.get('code')
        if not code:
            return Response({'message': '缺少code'}, status=status.HTTP_400_BAD_REQUEST)
        # 1.1 创建qq登录工具对象
        oauthqq = OAuthQQ(client_id=settings.QQ_CLIENT_ID,
                          client_secret=settings.QQ_CLIENT_SECRET,
                          redirect_uri=settings.QQ_REDIRECT_URI)
        try:
            # 2.通过code向QQ服务器请求获取access_token
            access_token = oauthqq.get_access_token(code)
            # 3.通过access_token向QQ服务器请求获取openid
            openid = oauthqq.get_open_id(access_token)
        except Exception as error:
            logger.info(error)
            return Response({'message': 'QQ服务器异常'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        try:
            # 4.查询openid是否绑定过美多商城中的用户
            qqauth_model = QQAuthUser.objects.get(openid=openid)
        except QQAuthUser.DoesNotExist:
            # 如果openid没有绑定过美多商城中的用户
            # 把openid进行加密安全处理,再响应给浏览器,让它先帮我们保存一会
            openid_sin = generate_save_user_token(openid)
            return Response({'access_token': openid_sin})

        else:
            # 如果openid已经绑定过美多商城中的用户(生成jwt token直接让它登录成功)
            # 手动生成token

            jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER  # 加载生成载荷函数
            jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER  # 加载生成token函数
            # 获取user对象
            user = qqauth_model.user
            payload = jwt_payload_handler(user)  # 生成载荷
            token = jwt_encode_handler(payload)  # 根据载荷生成token

            response = Response({
                'token': token,
                'username': user.username,
                'user_id': user.id
            })
            # 做cookie购物车合并到redis操作
            merge_cart_cookie_to_redis(request, user, response)

            return response

    def post(self, request):

        # 创建序列化器对象,进行反序列化
        serializer = QQAuthUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # 手动生成jwt Token
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER  # 加载生成载荷函数
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER  # 加载生成token函数
        # 获取user对象

        payload = jwt_payload_handler(user)  # 生成载荷
        token = jwt_encode_handler(payload)  # 根据载荷生成token

        response = Response({
            'token': token,
            'username': user.username,
            'user_id': user.id
        })
        # 做cookie购物车合并到redis操作
        merge_cart_cookie_to_redis(request, user, response)

        return response


class QQAuthURLView(APIView):
    """生成QQ扫码url"""

    def get(self, request):
        # 1.获取next(从那里去到login界面)参数路径
        next = request.query_params.get('next')
        if not next:  # 如果没有指定来源将来登录成功就回到首页
            next = '/'

        # QQ登录参数
        """
        QQ_CLIENT_ID = '101514053'
        QQ_CLIENT_SECRET = '1075e75648566262ea35afa688073012'
        QQ_REDIRECT_URI = 'http://www.meiduo.site:8080/oauth_callback.html'
        oauthqq = OAuthQQ(client_id='101514053', 
                  client_secret='1075e75648566262ea35afa688073012', 
                  redirect_uri='http://www.meiduo.site:8080/oauth_callback.html',
                  state=next)
        """

        # 2.创建QQ登录sdk 的对象
        oauthqq = OAuthQQ(client_id=settings.QQ_CLIENT_ID,
                          client_secret=settings.QQ_CLIENT_SECRET,
                          redirect_uri=settings.QQ_REDIRECT_URI,
                          state=next)
        # 3.调用它里面的get_qq_url方法来拿到拼接好的扫码链接
        login_url = oauthqq.get_qq_url()

        # 4.把扫码url响应给前端
        return Response({'login_url': login_url})
