# -*- coding: utf-8 -*-
import os, sys, time, datetime, pstats, shutil, json, argparse, logging, stat, pathlib, string, random, qiniu, http, \
    threading, filetype, hashlib, re, pprint, operator
from functools import wraps, partial
from collections import namedtuple, Counter, defaultdict, OrderedDict, deque
from django.shortcuts import render
from django.views.generic import View
from django.contrib.auth.decorators import login_required, permission_required
from django.db import transaction, IntegrityError
from django.http.response import HttpResponse, Http404, HttpResponseForbidden, HttpResponseBadRequest, JsonResponse
from django.http.request import HttpRequest
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.static import serve as downloadServer
from django.conf import settings
from main.conf import default, local
from main import generic, common
from fengtai.utils import tools, requestForms, error, dbRouter


# Create your views here.

class Debug(View, metaclass=tools.SingleInstance):
    def dispatch(self, request, *args, **kwargs):
        self.action = action = kwargs['path'].split('/')[0] if kwargs['path'] else None
        return super(Debug, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if self.action == 'numericID':
            return tools.genErrorStatusResponse(error.status_200, **{'id': tools.ID.genUniqueid(), "this": id(self)})
        elif self.action == 'menu':
            return tools.genErrorStatusResponse(error.status_200, **{"id": id(common.menus)})
        elif self.action == 'identity':
            return generic.identityCheckInfo(request)
        elif self.action == 'download':
            response = downloadServer(request, path='186014102512110微信图片_20191017133828.png',
                                      document_root=settings.ACCESSORIES,
                                      show_indexes=True)
            response['Content-Disposition'] = 'attachment; filename={!s}'.format('测试中使用.zip')
            return response
        elif self.action == 'message':
            return common.messageDebug(request)
        return HttpResponse(status=404, content="not found ....")


# 重定向路徑
class RedirectTo(View, metaclass=tools.SingleInstance):
    def get(self, request, *args, **kwargs):
        return tools.genErrorStatusResponse(error.status_redictTo, **{"url": "/", })


class UserEntry(View):
    """
        用户登录,退出
    """

    @method_decorator([csrf_exempt, ])
    def dispatch(self, request, *args, **kwargs):
        self.action = action = kwargs['path'].split('/')[0] if kwargs['path'] else None
        return super(UserEntry, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if self.action == 'nonceStr':
            data = tools.getNonceStr(request)
            return tools.genErrorStatusResponse(error.status_200, **data)
        elif self.action == 'verifyCode':
            return tools.getVerifyCode(request)
        elif self.action == 'logout':
            return generic.userLogout(request)
        elif self.action == 'notification':
            return generic.userNotification(request)
        elif self.action == 'notificationDetail':
            return generic.notificationDetail(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def post(self, request, *args, **kwargs):
        if self.action == 'login':
            return generic.userLogin(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def delete(self, request, *args, **kwargs):
        if self.action == 'notification':
            return generic.clearAllNotification(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)


# 功能入口处
class ItemProcess(View, metaclass=tools.SingleInstance):

    def checkActions(self):
        def inner(actions, codenames):
            """
            :param actions: 传递过来的路径list
            :param codenames: 根据default.basicRoleGroup 生成对应的str dict
            :return:
            """
            ds = []
            tail = None
            for index, val in enumerate(actions):
                if val not in codenames:
                    if len(codenames) == 0:
                        tail = val
                        break
                    else:
                        raise Exception(f"found codename error {val}")
                else:
                    ds.append(val)
                codenames = codenames[val]
            return ds, tail

        only = common.menus.funs_only_codename
        codenames, tail = inner(self.actions, only)
        return codenames, tail

    @method_decorator([login_required(), csrf_exempt])
    def dispatch(self, request, *args, **kwargs):
        self.actions = kwargs['path'].split('/') if kwargs['path'] else None
        if self.actions:
            self.actions = [*filter(lambda x: True if x else False, self.actions)]
        try:
            self.actions, self.tail = self.checkActions()
        except Exception as e:
            if default.debug:
                print(f"in the ItemProcess dispatch found error {e} ")
            return tools.genErrorStatusResponse(error.status_unAuthorized)
        kwargs['tail'] = self.tail
        if default.debug:
            print(f"in the ItemProcess dispatch actions:{self.actions}, tail:{self.tail}")
        with dbRouter.in_database('subordinate'):
            for group in request.user.groups.all():
                objs = group.permissions.filter(codename__in=self.actions)
                if objs.count() != len(self.actions):
                    return tools.genErrorStatusResponse(error.status_unAuthorized)
        return super(ItemProcess, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        return detailProcess(request, self.actions, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return detailProcess(request, self.actions, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return detailProcess(request, self.actions, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        return detailProcess(request, self.actions, *args, **kwargs)


@method_decorator([login_required, ], name='dispatch')
class Sundries(View, metaclass=tools.SingleInstance):
    """
        系统默认参数
    """

    def get(self, request, *args, **kwargs):
        return generic.getSundries(request)


@generic.operation
def detailProcess(request: HttpRequest, actions: list, *args, **kwargs):
    """
        功能处理
    :param request:@@
    :param actions:[system,account,district]
    :return:
    """
    # 功能菜单深度
    actions_len = len(actions)
    main, second, ternary, fourth, fiveth = [None for _ in range(5)]
    if actions_len == 1:
        main = actions[0]
    # 二级功能菜单
    elif actions_len == 2:
        main, second = actions
    # 三级功能菜单
    elif actions_len == 3:
        main, second, ternary = actions
    # 四级功能菜单
    elif actions_len == 4:
        main, second, ternary, fourth = actions
    # 五级功能菜单
    elif actions_len == 5:
        main, second, ternary, fourth, fiveth = actions
    # 首页
    if main == local.home.name:
        if second == local.lastestPolicyEntry.name:
            return generic.HomeContent.as_view()(request, *args, **kwargs)
        elif second == local.media.name:
            return generic.HomeContent.as_view()(request, *args, **kwargs)
    # 政策发布
    elif main == local.polices.name:
        if second == local.elderPolicy.name:
            if ternary == local.lastestPolicy.name:
                return generic.LastePolicy.as_view()(request, *args, **kwargs)
            elif ternary == local.policyRelease.name:
                return generic.PolicyRelease.as_view()(request, *args, **kwargs)
    # 资料查询
    elif main == local.information.name:
        if second == local.olderInfo.name:
            if ternary == local.olderQuery.name:
                return generic.olderQuery.as_view()(request, *args, **kwargs)
            elif ternary == local.olderManage.name:
                return generic.olderManage.as_view()(request, *args, **kwargs)
            elif ternary == local.olderHealthArchive.name:
                return generic.olderHealthArchive.as_view()(request, *args, **kwargs)

        elif second == local.institutionInfo.name:
            if ternary == local.institutionQuery.name:
                return generic.InstitutionQuery.as_view()(request, *args, **kwargs)
            elif ternary == local.institutionManage.name:
                return generic.InstitutionManage.as_view()(request, *args, **kwargs)
            elif ternary == local.olderDataVisual.name:
                return generic.olderDataVisual.as_view()(request, *args, **kwargs)
            elif ternary == local.institutionCareCenter.name:
                kwargs.update({'institutionType': 1})
                return generic.InstitutionCareCenter.as_view()(request, *args, **kwargs)
            elif ternary == local.institutionElderStation.name:
                kwargs.update({'institutionType': 3})
                return generic.InstitutionElderStation.as_view()(request, *args, **kwargs)
        elif second == local.financialInvest.name:
            if ternary == local.financialQuery.name:
                return generic.FinancialQuery.as_view()(request, *args, **kwargs)
            elif ternary == local.financialManage.name:
                return generic.FinancialManage.as_view()(request, *args, **kwargs)
        elif second == local.callCenter.name:
            if ternary == local.callCenterRecord.name:
                return generic.CallCenterManage.as_view()(request, *args, **kwargs)
    elif main == local.system.name:
        # 个人中心
        if second == local.personCenter.name:
            if ternary == local.myAccountInfo.name:
                return generic.personCenter.as_view()(request, *args, **kwargs)
            elif ternary == local.modifyPassword.name:
                return generic.personCenter.as_view()(request, *args, **kwargs)
        # 系统
        elif second == local.account.name:
            if ternary == local.district.name:
                return generic.Districts.as_view()(request, *args, **kwargs)
            elif ternary == local.role.name:
                return generic.Roles.as_view()(request, *args, **kwargs)
            elif ternary == local.users.name:
                return generic.Users.as_view()(request, *args, **kwargs)
        # 日志管理
        elif second == local.logging.name:
            if ternary == local.logInquery.name:
                return generic.Logging.as_view()(request, *args, **kwargs)
    elif main == local.dataMap.name:
        return generic.DataMap.as_view()(request, *args, **kwargs)
    return tools.genErrorStatusResponse(error.status_unAuthorized)
