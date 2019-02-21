from django.shortcuts import render
from drf_haystack.viewsets import HaystackViewSet
from rest_framework.generics import ListAPIView, GenericAPIView
from rest_framework.filters import OrderingFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from orders.models import OrderInfo

from meiduo.utils.paginations import StandardResultsSetPagination
from .models import SKU
from .serializers import SKUSerializer, SKUSearchSerializer, OrderCenterSerializer


# Create your views here.

# 方法二
class OrederCenterView(GenericAPIView):
    """订单中心"""
    # 允许登陆用户访问
    permission_classes = [IsAuthenticated]
    # 指定序列化器的类
    serializer_class = OrderCenterSerializer
    # 指定分页的类
    pagination_class = StandardResultsSetPagination

    # 指定查询集
    def get_queryset(self):
        user = self.request.user
        return OrderInfo.objects.filter(user_id=user.id)

    def get(self, request):

        orders = self.get_queryset()
        # 分页
        page = self.paginate_queryset(orders)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(orders, many=True)
        # 构建响应数据
        rest = dict(results=serializer.data)
        # 返回响应数据
        return Response(rest)

# 方法一
# class OrederCenterView(APIView):
#     """订单中心"""
#
#
#     # 登陆用户才可以访问
#     permission_classes = [IsAuthenticated]
#
#     def get(self, request):
#         # 获取当前登陆用户
#         user = request.user
#         # print(user.id)
#         # 查询用户订单数据
#         orders = OrderInfo.objects.filter(user_id=user.id).order_by('create_time')
#         # for order in orders:
#         # print(orders)
#
#         # 创建序列化器对象
#         serializer = OrderCenterSerializer(orders, many=True)
#         # print(serializer.data)
#         rest = dict(results=serializer.data)
#         return Response(rest)


# /categories/(?P<category_id>\d+)/skus?page=xxx&page_size=xxx&ordering=xxx
class SKUListView(ListAPIView):
    """商品列表界面"""

    # 指定序列化器
    serializer_class = SKUSerializer
    # 指定过滤后端为排序
    filter_backends = [OrderingFilter]
    # 指定排序字段
    ordering_fields = ['create_time', 'price', 'sales']

    # 指定查询集
    # queryset = SKU.objects.filter(is_launched=True, category_id=category_id)

    def get_queryset(self):
        category_id = self.kwargs.get('category_id')  # 获取url路径中的正则组别名提取出来的参数
        return SKU.objects.filter(is_launched=True, category_id=category_id)


class SKUSearchViewSet(HaystackViewSet):
    """
    SKU搜索
    """
    index_models = [SKU]

    serializer_class = SKUSearchSerializer



