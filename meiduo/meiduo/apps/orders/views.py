from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django_redis import get_redis_connection
from decimal import Decimal
from rest_framework.response import Response
from rest_framework.generics import CreateAPIView
from rest_framework import serializers
import re

from goods.models import SKU
from .serializers import OrderSettlementSerializer, CommitOrderSerializer, UncommentOrderGoodsSerializer, \
    CommentGoodsSerializer
from .models import OrderInfo, OrderGoods


# Create your views here.

class SKUCommemtsView(APIView):
    """获取某个SKU下所有评论信息"""

    def get(self, request, sku_id):
        # 获取sku
        try:
            sku = SKU.objects.get(id=sku_id)
        except SKU.DoesNotExist:
            raise serializers.ValidationError('sku_id有误')

        order_goods = OrderGoods.objects.filter(sku=sku, is_commented=True)
        comment_score_list = []
        for order_good in order_goods:
            comment_score_dict = {}
            comment_score_dict['score'] = order_good.score
            comment_score_dict['comment'] = order_good.comment
            # 需要将用户名模糊处理
            username = order_good.order.user.username
            result = result = username[0] + '***' + username[len(username) - 1]
            comment_score_dict['username'] = result

            comment_score_list.append(comment_score_dict)

        return Response(comment_score_list)


class UncommentGoodsView(APIView):
    """获取某一订单下所有未评论商品信息"""

    permission_classes = [IsAuthenticated]

    def get(self, request, order_id):
        # 获取user
        user = request.user

        # 通过order_id, user查询未评论完的订单信息
        status = OrderInfo.ORDER_STATUS_ENUM['UNCOMMENT']
        try:
            order_info = OrderInfo.objects.get(order_id=order_id, user=user, status=status)
        except OrderInfo.DoesNotExist:
            raise serializers.Serializer('order_id无效')

        uncomment_dict = []
        # 筛选出所有未评论数据
        for order_good in order_info.skus.all().filter(is_commented=False):
            sku = order_good.sku
            sku_dict = {
                'sku': {
                    'id': sku.id,
                    'name': sku.name,
                    'default_image_url': sku.default_image_url
                },
                'price': order_good.price
            }
            uncomment_dict.append(sku_dict)

        return Response(uncomment_dict)


class GoodsJudgeView(APIView):
    """订单商品评论"""
    permission_classes = [IsAuthenticated]

    def post(self, request, order_id):
        serializer = CommentGoodsSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        order = serializer.validated_data.get('order')
        sku = serializer.validated_data.get('sku')
        score = serializer.validated_data.get('score')
        comment = serializer.validated_data.get('comment')
        is_anonymous = serializer.validated_data.get('is_anonymous')

        # 更新订单商品
        OrderGoods.objects.filter(order=order, sku=sku, is_commented=False).update(score=score,
                                                                                   comment=comment,
                                                                                   is_anonymous=is_anonymous,
                                                                                   is_commented=True)
        # 如果订单下所有订单商品都已评论，更新订单状态
        count = OrderGoods.objects.filter(order=order, is_commented=False).count()

        if count == 0:
            order.status = OrderInfo.ORDER_STATUS_ENUM['FINISHED']
            order.save()

        # 更新sku, goods评论量
        sku.comments += 1
        sku.goods.comments += 1
        sku.save()
        sku.goods.save()

        return Response({'message': '提交评论成功'})


class CommitOrderView(CreateAPIView):
    # 指定权限
    permission_classes = [IsAuthenticated]

    # 指定序列化器
    serializer_class = CommitOrderSerializer


class OrderSettlementView(APIView):
    """去结算接口"""

    permission_classes = [IsAuthenticated]  # 给视图指定权限

    def get(self, request):
        """获取"""
        user = request.user

        # 从购物车中获取用户勾选要结算的商品信息
        redis_conn = get_redis_connection('cart')
        redis_cart = redis_conn.hgetall('cart_%s' % user.id)
        cart_selected = redis_conn.smembers('selected_%s' % user.id)
        cart = {}
        for sku_id in cart_selected:
            cart[int(sku_id)] = int(redis_cart[sku_id])

        # 查询商品信息
        skus = SKU.objects.filter(id__in=cart.keys())
        for sku in skus:
            sku.count = cart[sku.id]

        # 运费
        freight = Decimal('10.00')
        # 创建序列化器时 给instance参数可以传递(模型/查询集(many=True) /字典)
        serializer = OrderSettlementSerializer({'freight': freight, 'skus': skus})

        return Response(serializer.data)
