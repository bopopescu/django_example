# -*- coding: utf-8 -*-
import os, sys, time, datetime, json, string, struct, pathlib, pprint, random, dateutil, ast, filetype, glob, shutil, \
    hashlib, signal
import pandas as pd
import numpy as np
from urllib.parse import urlencode, quote, quote_plus
from dateutil import rrule, relativedelta
from django.http.response import Http404, HttpResponse
from django.http.request import HttpRequest
from functools import partial, lru_cache, reduce
from collections import OrderedDict, defaultdict, Counter, namedtuple
from django.db import transaction, IntegrityError
from django.http import QueryDict
from django.utils.encoding import escape_uri_path
from django.db.models.aggregates import Max, Count
from django.utils.timezone import make_aware
from django.conf import settings
from django.db.models import F, Q, When
from django.core.cache import cache
from celery.result import AsyncResult
from django.forms.models import model_to_dict
from django.contrib.auth.hashers import make_password, check_password
from celery.utils.functional import first
from django.views.static import serve as downloadServer
from enum import Enum
from fengtai.utils import tools, dbRouter, error, requestForms
from main import models, tasks
from django.contrib.auth import models as djmodel
from main.conf import default, local


class Menus(metaclass=tools.SingleInstance):
    """
        这一块是对菜单功能的处理
    """

    def __init__(self):
        self.funs = OrderedDict(default.basicRoleGroup)
        self.funs_only_codename = self.__onlyCodename()
        self.roles = self.__onlyRoles()

    def __onlyCodename(self):
        """
            最大权限集合
        :return:
        """

        def inner(data: Enum, ds):
            for i in data:
                name = i.name
                ds[name] = {}
                inner(data[i], ds[name])

        jd = default.basicRoleGroup[local.super]
        ds = {}
        inner(jd, ds)
        return ds

    def __onlyRoles(self):
        return {i.name: i.value for i in self.funs}

    @property
    def funcs(self):
        return self.funs


menus = Menus()


def messageDebug(request):
    from django.contrib import messages
    messages.add_message(request, 40, 'A serious error occurred.')
    return HttpResponse("good sucesss with message")


def getSubPermissions(data: Enum, defaultPerms: dict, flag=False):
    """
        递归获取用户的功能菜单
    :param data:
    :param defaultPerms:
    :return:
    """

    class Detail(tools.BaseData):
        pass

    ds = []
    for k, v in data.items():
        # if k.name not in defaultPerms:
        #     continue
        dt = Detail()
        if flag:
            dt.enabled = 1 if k.name in defaultPerms else 0
        else:
            dt.enabled = 0
        # dt.codename, dt.name = k.name, defaultPerms[k.name]
        dt.codename, dt.name = k.name, getattr(local, k.name).value if getattr(local, k.name, None) else ''
        dt.sub = []
        ret = getSubPermissions(v, defaultPerms, flag)
        for it in ret:
            dt.sub.append(it)
        if not dt.sub:
            delattr(dt, 'sub')
        ds.append(dt.toJson)
    return ds


def userPermission(user):
    oDict = menus.funs
    roles = {i.name: i for i in oDict}
    perms = {}
    for g in user.groups.all():
        for p in g.permissions.all().values_list('codename', 'name'):
            codename, name = p
            perms[codename] = name
        data = getSubPermissions(data=oDict[roles[g.genre]], defaultPerms=perms, flag=True)
        return data


def groupPermission(group):
    oDict = menus.funs
    roles = {i.name: i for i in oDict}
    perms = {}
    for p in group.permissions.all().values_list('codename', 'name'):
        codename, name = p
        perms[codename] = name
    data = getSubPermissions(data=oDict[roles[group.genre]], defaultPerms=perms, flag=True)
    return data


def checkCustomerizedPerms(data, name):
    """
    :param data:用户提交的json字符串,
    :param name:group name
    :return:
    """

    def inner(perms, base):
        """
        :param perms: 用户提交的权限
        :param base: group 对应的基础权限
        :return:
        """
        ds = []
        defaltPerms = {k.name: base[k] for k in base}
        for i in perms:
            codename, enabled = i['codename'], i['enabled']
            if codename not in defaltPerms or enabled not in {0, 1}:
                raise Exception("found error codename {}".format(codename))
            if enabled:
                ds.append(codename)
            # else:
            #     continue
            if 'sub' in i:
                inner_perms = inner(i['sub'], defaltPerms[codename])
                # if not inner_perms:
                #     ds.pop()
                for x in inner_perms:
                    ds.append(x)

        return ds

    try:
        jdata = json.loads(data)
    except json.JSONDecodeError as e:
        if default.debug:
            print(f"in the checkCustomerizedPerms json decode error {e}")
        return None
    roles = {i.name: menus.funcs[i] for i in menus.funcs}
    try:
        perms = inner(jdata, roles[name])
    except Exception as e:
        if default.debug:
            print(f"in the checkCustomerizedPerms found error {e}")
        return None
    return perms


@dbRouter.in_database("subordinate")
def getDistricts(locationid=0, *args, **kwargs):
    ds = []
    mx = max(default.belongs.keys())
    for son in models.District.objects.filter(ora_parent=locationid).order_by('-ora_weight').iterator():
        dt = tools.BaseData()
        parentids = kwargs['parentids'] if 'parentids' in kwargs else None
        parentName = ' '.join(list(args))
        # parentids = parentids + [son.ora_index, ] if parentids else [locationid, son.ora_index]
        dt.id, dt.name, dt.parent, dt.weight, dt.level_name, \
        dt.status, dt.level = son.ora_index, son.ora_name, parentName, son.ora_weight, \
                              default.belongs[
                                  son.ora_level].value if son.ora_level in default.belongs else '', son.ora_status, son.ora_level
        # dt.parentid = parentids
        dt.fatherid = son.ora_parent
        ds.append(dt.toJson)
        if son.ora_level >= mx:
            continue
        for i in getDistricts(son.ora_index, parentName, son.ora_name, parentids=parentids):
            ds.append(i)
    return ds


def getDistrictList(request):
    """
        返回地区列表,分页信息,super user可以看到所有,具体的街道可以看到自己及下属区域
    :param request:
    :return:
    """
    form = requestForms.Page(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    page, size = form.cleaned_data['page'], form.cleaned_data['size']
    slice_ = tools.getPageSlice(size, page)
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        data = getDistricts(default.defaultDetailLocations[0], default.defaultDetailLocations[1])
    else:
        data = getDistricts(request.user.locate.ora_index, request.user.locate.ora_name)
    total = len(data)
    ret = data[slice_]
    return tools.genErrorStatusResponse(error.status_200, data=ret, **{'total': total})


def getDistrictLevel(request):
    """
        获取创建地区时的区域类型
    :param request:
    :return:
    """
    ds = []
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        for k, v in default.belongs.items():
            if k > default.defaultDetailLocations[2]:
                dt = tools.BaseData()
                dt.level = k
                dt.name = v.value
                ds.append(dt.toJson)
    else:
        for k, v in default.belongs.items():
            if k > request.user.locate.ora_level:
                dt = tools.BaseData()
                dt.level = k
                dt.name = v.value
                ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds)


@dbRouter.in_database("subordinate")
def getDistrictHierarchy(request):
    def hierarchy(location, level_val):
        ds = []
        mx = max(default.belongs.keys())
        for son in models.District.objects.filter(ora_parent=location).order_by('-ora_weight').iterator():
            dt = tools.BaseData()
            dt.id, dt.name, dt.level = son.ora_index, son.ora_name, son.ora_level
            dt.sub = []
            if son.ora_level > level_val:
                continue
            if son.ora_level == mx:
                delattr(dt, 'sub')
                ds.append(dt.toJson)
                continue

            for i in hierarchy(son.ora_index, level_val):
                dt.sub.append(i)
            if not dt.sub:
                delattr(dt, 'sub')
            ds.append(dt.toJson)
        return ds

    form = requestForms.CreateDistrictWithLevel(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    level = form.cleaned_data['level']
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        root = models.District.objects.get(ora_index=default.defaultDetailLocations[0])
    else:
        root = request.user.locate
    if level < root.ora_level:
        return tools.genErrorStatusResponse(error.status_notAllowed)
    dt = tools.BaseData()
    dt.id, dt.name = root.ora_index, root.ora_name
    data = hierarchy(dt.id, level - 1)
    if data:
        dt.sub = data
    return tools.genErrorStatusResponse(error.status_200, data=[dt.toJson, ])


def checkCreateUserRole(role, request):
    """
        创建用户,角色获取
    :param request:
    :return:
    """
    genre = request.user.groups.all()[0].genre
    ds: dict = {}
    if genre in {local.super.name, local.systemAdmin.name}:
        for r in models.WebGroup.objects.all():
            ds[r.name] = r.genre
    else:
        for r in request.user.groups.all():
            genre = r.genre
            found = False
            for i in menus.roles:
                if found or i == genre:
                    for g in models.WebGroup.objects.filter(genre=i):
                        ds[g.name] = g.genre
                    found = True
    if role not in ds:
        return False, None
    return True, ds[role]


@dbRouter.in_database('subordinate')
def getDistrictHierarchyForCreateUser(request):
    """
        获取地区层级
    :param request:
    :return:
    """

    def hierarchy(location, level_val):
        ds = []
        mx = max(default.belongs.keys())
        for son in models.District.objects.filter(Q(ora_parent=location) & Q(ora_status=1)).order_by(
                '-ora_weight').iterator():
            dt = tools.BaseData()
            dt.id, dt.name = son.ora_index, son.ora_name
            dt.sub = []
            if son.ora_level > level_val:
                continue
            if son.ora_level == mx:
                delattr(dt, 'sub')
                ds.append(dt.toJson)
                continue

            for i in hierarchy(son.ora_index, level_val):
                dt.sub.append(i)
            if not dt.sub:
                delattr(dt, 'sub')
            ds.append(dt.toJson)
        return ds

    form = requestForms.CreateUserWithRole(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    genre = form.cleaned_data['genre']
    found, genre = checkCreateUserRole(genre, request)
    if not found:
        return tools.genErrorStatusResponse(error.status_checkValueError)
    levelMap = {v: k for k, v in default.belongs.items()}
    level = -1
    if genre == local.systemAdmin.name:
        level = default.defaultLocation[2]
        return tools.genErrorStatusResponse(error.status_200, data=None)
    elif genre in {local.countyAdmin.name, }:
        level = levelMap[local.district_level]
    elif genre in {local.streetAdmin.name, }:
        level = levelMap[local.street]
    elif genre in {local.communityAdmin.name, }:
        level = levelMap[local.community]

    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        root = models.District.objects.get(ora_index=default.defaultDetailLocations[0])
    else:
        root = request.user.locate
    dt = tools.BaseData()
    dt.id, dt.name = root.ora_index, root.ora_name
    data = hierarchy(dt.id, level)
    dt.sub = data
    if not dt.sub:
        delattr(dt, 'sub')
    return tools.genErrorStatusResponse(error.status_200, data=[dt.toJson, ])


@dbRouter.in_database('subordinate')
def usersDynamicSearch(request):
    """
        用户动态搜索
    :param request:
    :return:
    """
    form = requestForms.UsersDynamic(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    name = form.cleaned_data['name']
    page = form.cleaned_data['page']
    size = form.cleaned_data['size']

    try:
        slice_ = tools.getPageSlice(size, page)
    except Exception as e:
        if default.debug:
            print(f"in the usersDynamicSearch parse error {e}")
        return tools.genErrorStatusResponse(error.status_checkValueError)
    ds: list = []
    query = Q()
    exclude = Q()
    genre = request.user.groups.all()[0].genre
    query |= Q(username__iregex=name)
    query |= Q(last_name__iregex=name)
    genre_sets = set()
    found = False
    for key in menus.funcs:
        if found:
            genre_sets.add(key.name)
            continue
        if key.name == genre:
            genre_sets.add(key.name)
            found = True
            continue
    if genre in {local.super.name, local.systemAdmin.name, local.countyAdmin.name}:
        query &= Q(groups__genre__in=genre_sets)
    else:
        query &= Q(groups__genre__in=genre_sets) & Q(locate__ora_index=request.user.locate.ora_index)
    exclude |= Q(username=default.superName)
    exclude |= Q(username=request.user.username)

    total = models.WebUser.objects.exclude(exclude).filter(query).count()
    for user in models.WebUser.objects.exclude(exclude).filter(query).order_by('createTime')[slice_]:
        dt = tools.BaseData()
        dt.username, dt.name_zh, dt.role, dt.role_zh, dt.isActive = user.username, user.last_name, \
                                                                    user.groups.all()[0].name, user.groups.all()[
                                                                        0].name_zh, 1 if user.is_active else 0
        dt.belong = ' '.join([*reversed(getBelong(user.locate.ora_index))]) if user.locate else None
        dt.belongid = [*reversed(getBelong(user.locate.ora_index, onlyIndex=True)), ] if user.locate else None
        dt.phone = user.phone
        dt.email = user.email
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds, **{'total': total})


@dbRouter.in_database('subordinate')
def userDynamicAdvancedSearch(request):
    """
        用户管理动态高级搜索
    :param request:
    :return:
    """
    form = requestForms.UsersHighDynamic(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    name = form.cleaned_data['name']
    page = form.cleaned_data['page']
    size = form.cleaned_data['size']
    username = form.cleaned_data['username']
    belongTo = form.cleaned_data['belongTo']
    locate = form.cleaned_data['locate']
    status = form.cleaned_data['status']
    role = form.cleaned_data['role']

    query = Q()
    exclude = Q()
    genre = request.user.groups.all()[0].genre
    genre_sets = set()
    found = False
    for key in menus.funcs:
        if found:
            genre_sets.add(key.name)
            continue
        if key.name == genre:
            genre_sets.add(key.name)
            found = True
            continue
    if genre in {local.super.name, local.systemAdmin.name}:
        query &= Q(groups__genre__in=genre_sets)
    else:
        if genre in {local.countyAdmin.name}:
            query &= Q(groups__genre__in=genre_sets)
        else:
            query &= Q(groups__genre__in=genre_sets) & Q(locate__ora_index=request.user.locate.ora_index)
    exclude |= Q(username=default.superName)
    exclude |= Q(username=request.user.username)
    try:
        slice_ = tools.getPageSlice(size, page)
        query &= Q(username__iregex=username) if username else Q()
        query &= Q(last_name__iregex=name) if name else Q()
        query &= Q(groups__name=role) if role else Q()
        # {"全部": 1, "启用": 2, "禁用": 3}
        if status == 1:
            pass
        elif status == 2:
            query &= Q(is_active=True)
        elif status == 3:
            query &= Q(is_active=False)
        # belongTo 1:全部,2:无,3:特定区域
        if belongTo == 4:
            query &= Q(locate__ora_index=locate) if locate else Q()
        elif belongTo == 3:
            query &= Q(locate__ora_index=default.defaultDetailLocations[0])
        elif belongTo == 2:
            query &= Q(locate=None)
        elif belongTo == 1:
            pass
    except Exception as e:
        if default.debug:
            print(f"in the usersDynamicSearch parse error {e}")
        return tools.genErrorStatusResponse(error.status_checkValueError)
    ds: list = []
    total = models.WebUser.objects.exclude(exclude).filter(query).count()
    for user in models.WebUser.objects.exclude(exclude).filter(query).order_by('createTime')[slice_]:
        dt = tools.BaseData()
        dt.username, dt.name_zh, dt.role, dt.role_zh, dt.isActive = user.username, user.last_name, \
                                                                    user.groups.all()[0].name, user.groups.all()[
                                                                        0].name_zh, 1 if user.is_active else 0
        dt.belong = ' '.join([*reversed(getBelong(user.locate.ora_index))]) if user.locate else None
        dt.belongid = [*reversed(getBelong(user.locate.ora_index, onlyIndex=True)), ] if user.locate else None
        dt.phone = user.phone
        dt.email = user.email
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds, **{"total": total})


@dbRouter.in_database('subordinate')
def userAdvancedDynamicParam(request):
    """
        用户管理动态搜索信息获取
    :param request:
    :return:
    """

    def hierarchy(location):
        ds = []
        mx = max(default.belongs.keys())
        for son in models.District.objects.filter(Q(ora_parent=location) & Q(ora_status=1)).order_by(
                '-ora_weight').iterator():
            dt = tools.BaseData()
            dt.id, dt.name = son.ora_index, son.ora_name
            dt.sub = []
            if son.ora_level == mx - 1:
                delattr(dt, 'sub')
                ds.append(dt.toJson)
                continue

            for i in hierarchy(son.ora_index):
                dt.sub.append(i)
            if not dt.sub:
                delattr(dt, 'sub')
            ds.append(dt.toJson)
        return ds

    # 角色列表
    roles = []
    exclude_set = menus.roles.keys()
    genre = request.user.groups.all()[0].genre
    return_data = tools.BaseData()
    if genre in {local.super.name, local.systemAdmin.name}:
        root = models.District.objects.get(ora_index=default.defaultDetailLocations[0])
        belongTo_map = {"全部": 1, "无": 2, "丰台区": 3, "特定街道": 4}
        return_data.districts = hierarchy(root.ora_index)

        for r in models.WebGroup.objects.exclude(name__in=exclude_set).filter(isActive=True).order_by('createTime'):
            dt = tools.BaseData()
            dt.name = r.name
            dt.name_zh = r.name_zh
            roles.append(dt.toJson)

    else:
        root = request.user.locate
        if genre in {local.countyAdmin.name}:
            belongTo_map = {"全部": 1, "无": 2, "丰台区": 3, "特定街道": 4}
            return_data.districts = hierarchy(root.ora_index)
        else:
            belongTo_map = {"全部": 1, "无": 2}
            return_data.districts = None

        for r in request.user.groups.all():
            genre = r.genre
            found = False
            for i in menus.roles:
                if found or i == genre:
                    for g in models.WebGroup.objects.exclude(name__in=exclude_set).filter(
                            Q(genre=i) & Q(isActive=True)).order_by('createTime'):
                        dt = tools.BaseData()
                        dt.name_zh = g.name_zh
                        dt.name = g.name
                        roles.append(dt.toJson)
                    found = True
    return_data.roles = roles
    status_map = {"全部": 1, "启用": 2, "禁用": 3}
    return_data.status: list = []
    for k, v in status_map.items():
        item = tools.BaseData()
        item.id = v
        item.name = k
        return_data.status.append(item.toJson)
    return_data.belongTo: list = []
    for k, v in belongTo_map.items():
        item = tools.BaseData()
        item.id = v
        item.name = k
        return_data.belongTo.append(item.toJson)

    return tools.genErrorStatusResponse(error.status_200, return_data.toJson)


def detailDistrict(request):
    form = requestForms.IDForm(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    id_ = form.cleaned_data['id']
    objs = models.District.objects.filter(ora_index=id_)
    if not objs.exists():
        return tools.genErrorStatusResponse(error.status_notFound)
    dt = tools.BaseData()
    dt.name, dt.id, dt.level, dt.status, dt.parent = objs[0].ora_name, objs[0].ora_index, objs[0].ora_level, objs[
        0].ora_status, objs[
                                                         0].ora_parent
    return tools.genErrorStatusResponse(error.status_200, **dt.toJson)


def districtOrder(request):
    """
        地区排序
    :param request:
    :return:
    """
    form = requestForms.IDForm(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    id_ = form.cleaned_data['id']
    ds = []
    for i in models.District.objects.filter(Q(ora_parent=id_)).order_by('-ora_weight').iterator():
        dt = tools.BaseData()
        dt.name, dt.id, dt.weight = i.ora_name, i.ora_index, i.ora_weight
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, data=ds)


def districtDynamicSearch(request):
    """
        地区动态管理
    :param request:
    :return:
    """
    form = requestForms.DistrictDynamic(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    page = form.cleaned_data['page']
    size = form.cleaned_data['size']
    name = form.cleaned_data['name']
    try:
        slice_ = tools.getPageSlice(size, page)
    except Exception as e:
        if default.debug:
            print(f"in the districtDynamicSearch parse error")
        return tools.genErrorStatusResponse(error.status_checkValueError)
    ds: list = []
    total = models.District.objects.filter(Q(ora_name__iregex=name) & Q(ora_flag=1)).count()
    for item in models.District.objects.filter(Q(ora_name__iregex=name) & Q(ora_flag=1)).order_by('ora_weight')[slice_]:
        dt = tools.BaseData()
        dt.id, dt.name, dt.weight, dt.level, \
        dt.status = item.ora_index, item.ora_name, item.ora_weight, \
                    item.ora_level, item.ora_status
        dt.level_name = default.belongs[item.ora_level].value if item.ora_level in default.belongs else ''
        dt.fatherid = item.ora_parent
        dt.parent = ' '.join([*reversed(getBelong(item.ora_index))][:-1])
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds, **{'total': total})


def districtDelete(request):
    form = requestForms.IDForm(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    id_ = form.cleaned_data['id']
    rows = models.District.objects.filter(ora_index=id_).delete()
    if not rows:
        return tools.genErrorStatusResponse(error.status_notFound)
    return tools.genErrorStatusResponse(error.status_200)


def subDistrictChilds(id_):
    """
        判断地区id,是否在自己的下属区域里
    :param id_:
    :return:
    """
    ds = {}
    mx = max(default.belongs.keys())
    ds[id_] = ''
    for i in models.District.objects.filter(ora_parent=id_).iterator():
        ds[i.ora_index] = ''
        if i.ora_level >= mx:
            continue
        for n in subDistrictChilds(i.ora_index):
            ds[n] = ''
    return ds


def subRoleChilds(user):
    """
        判断角色是否在自己下属级别
    :param user:
    :return:
    """
    ds = {}
    for r in user.groups.all():
        genre = r.genre
        found = False
        for i in menus.roles:
            if found or i == genre:
                for g in models.WebGroup.objects.filter(genre=i).iterator():
                    ds[g.name] = ''
                found = True
    return ds


def districtUpdateOrCreate(request, created=False):
    """
        地区的创建或编辑
    :param request:
    :param created:
    :return:
    """

    form = requestForms.AddNewDistrict(QueryDict(request.body))
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    level, parent, name, status, id_ = form.cleaned_data['level'], form.cleaned_data['parent'], form.cleaned_data[
        'name'], \
                                       form.cleaned_data['status'], form.cleaned_data['id']
    if level not in default.belongs or status not in default.status:
        return tools.genErrorStatusResponse(error.status_checkValueError)
    # 只能创建自己的下属
    with dbRouter.in_database("subordinate"):
        if not models.District.objects.filter(ora_index=parent).exists():
            return tools.genErrorStatusResponse(error.status_notFound)
        genre = request.user.groups.all()[0].genre

        if genre not in {local.super.name, local.systemAdmin.name}:
            if level <= request.user.locate.ora_level:
                return tools.genErrorStatusResponse(error.status_notAllowed)
            if parent not in subDistrictChilds(request.user.locate.ora_index):
                return tools.genErrorStatusResponse(error.status_notAllowed)
    log = tools.BaseData()
    log.username = request.user.username
    if created:
        with transaction.atomic():
            for i in models.District.objects.filter(ora_parent=parent).iterator():
                if i.ora_name == name:
                    return tools.genErrorStatusResponse(error.status_foundDuplicateID)
            else:
                try:
                    while 1:
                        mx = models.District.objects.values('ora_index').aggregate(id=Max(F('ora_index')))
                        mx = mx["id"] + int(''.join(random.sample(string.digits, 2)))
                        if not models.District.objects.filter(ora_parent=mx).exists():
                            break
                    for parent_ in models.District.objects.filter(ora_index=parent):
                        if parent_.ora_level - level != -1:
                            raise Exception("found district level and parent not belong")
                    models.District.objects.create(ora_level=level, ora_name=name, ora_flag=1, ora_parent=parent,
                                                   ora_status=status,
                                                   ora_index=mx)
                except IntegrityError:
                    return tools.genErrorStatusResponse(error.status_foundDuplicateID)
                except Exception:
                    return tools.genErrorStatusResponse(error.status_checkValueError)
                log.action, log.content = local.log_addDistrict.value, str(request.body)
    else:
        with transaction.atomic():
            if id_ == default.defaultDetailLocations[0]:
                return tools.genErrorStatusResponse(error.status_unAuthorized)
            objs = models.District.objects.filter(ora_index=id_)
            if not objs.exists():
                return tools.genErrorStatusResponse(error.status_notFound)
            for obj in objs:
                if obj.ora_index == parent:
                    return tools.genErrorStatusResponse(error.status_checkValueError)
            update_values = {}
            if name:
                objs_ = models.District.objects.filter(Q(ora_parent=objs[0].ora_parent) & Q(ora_name=name))
                if objs_.exists():
                    for obj in objs_:
                        if obj.ora_index != id_:
                            return tools.genErrorStatusResponse(error.status_foundDuplicateID)
                update_values['ora_name'] = name
            if level:
                update_values['ora_level'] = level
            if parent:
                update_values['ora_parent'] = parent
            update_values['ora_status'] = status
            objs.update(**update_values)
            log.action, log.content = local.log_modifyDistrict.value, form.cleaned_data
    tasks.logRecord.delay(log.toJson)
    return tools.genErrorStatusResponse(error.status_200)


def modifyDistrictOrder(request):
    """
        childs={'id':weight,'id':weight}
    :param request:
    :return:
    """
    form = requestForms.DistrictOrder(QueryDict(request.body))
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    parent, childs = form.cleaned_data['parent'], form.cleaned_data['childs']
    try:
        childs = json.loads(childs)
    except Exception as e:
        if default.debug:
            print(f"in the modifyDistrictOrder found error {e}")
        return tools.genErrorStatusResponse(error.status_checkValueError)
    childs = {k['id']: k['weight'] for k in childs}
    try:
        with transaction.atomic():
            for i in models.District.objects.filter(Q(ora_parent=parent)):
                i.ora_weight = childs[i.ora_index]
                i.save()
    except Exception as e:
        if default.debug:
            print(f"in the modifyDistrictOrder found error {e}")
        return tools.genErrorStatusResponse(error.status_foundError)
    return tools.genErrorStatusResponse(error.status_200)


@dbRouter.in_database("subordinate")
def getBasicGenres(request):
    genre_set = set()
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        [*map(lambda x: genre_set.add(x.name), menus.funcs), ]
    else:
        for group in request.user.groups.all():
            found = False
            for base in menus.funcs:
                if found or base.name == group.genre:
                    found = True
                    genre_set.add(base.name)
    ds = []
    total = models.WebGroup.objects.exclude(name=local.super.name).filter(
        Q(isBasic=True) & Q(isActive=True) & Q(genre__in=genre_set)).count()
    for i in models.WebGroup.objects.exclude(name=local.super.name).filter(
            Q(isBasic=True) & Q(isActive=True) & Q(genre__in=genre_set)).order_by(
        'createTime').iterator():
        dt = tools.BaseData()
        dt.genre, dt.genre_zh, dt.permissions = i.name, i.name_zh, groupPermission(i)
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds, **{"total": total})


@dbRouter.in_database("subordinate")
def getRoles(request):
    """
        获取角色组
    :param request:
    :return:
    """
    form = requestForms.Page(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    page, size = form.cleaned_data['page'], form.cleaned_data['size']
    slice_ = tools.getPageSlice(size, page)
    genre_set = set()
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        [*map(lambda x: genre_set.add(x.name), menus.funcs), ]
    else:
        for group in request.user.groups.all():
            found = False
            for base in menus.funcs:
                if found or base.name == group.genre:
                    found = True
                    genre_set.add(base.name)
    ds = []
    exclude_set = menus.roles.keys()
    total = models.WebGroup.objects.exclude(name__in=exclude_set).filter(
        Q(genre__in=genre_set)).count()
    for i in \
            models.WebGroup.objects.exclude(name__in=exclude_set).filter(
                Q(genre__in=genre_set)).order_by(
                'createTime')[
                slice_]:
        dt = tools.BaseData()
        dt.name, dt.genre, dt.name_zh, dt.permissions = i.name, getattr(local,
                                                                        i.genre).value, i.name_zh, groupPermission(i)
        dt.isActive = 1 if i.isActive else 0
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds, **{"total": total})


def roleUpdateOrCreate(request, created=False):
    form = requestForms.CreateRole(QueryDict(request.body))
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    name, name_zh, permissions = form.cleaned_data['name'], form.cleaned_data['name_zh'], form.cleaned_data[
        'permissions']
    log = tools.BaseData()
    if created:
        perms = checkCustomerizedPerms(permissions, name)
        if not perms:
            return tools.genErrorStatusResponse(error.status_checkValueError)
        if models.WebGroup.objects.filter(name_zh=name_zh).exists():
            return tools.genErrorStatusResponse(error.status_foundDuplicateID)
        try:
            with transaction.atomic():
                newName = tools.ID.genUniqueid()
                obj = models.WebGroup.objects.create(isBasic=False, createTime=make_aware(datetime.datetime.now()),
                                                     name=str(newName), genre=name,
                                                     name_zh=name_zh, isActive=True)
                for p in djmodel.Permission.objects.filter(codename__in=perms):
                    obj.permissions.add(p)
                log.username, log.action, log.content = request.user.username, local.log_addRole.value, form.cleaned_data
        except Exception as e:
            if default.debug:
                print(f"in the roleUpdateOrCreate create found error {e}")
            return tools.genErrorStatusResponse(error.status_foundDuplicateID)
    else:
        group = models.WebGroup.objects.filter(name=name)
        if not group.exists():
            return tools.genErrorStatusResponse(error.status_notFound)
        try:
            perms = checkCustomerizedPerms(permissions, group[0].genre)
            # if not perms:
            #     return tools.genErrorStatusResponse(error.status_checkValueError)
            with transaction.atomic():
                olds = frozenset([p.codename for p in group[0].permissions.all()])
                news = frozenset(perms)
                for p in djmodel.Permission.objects.filter(codename__in=news - olds):
                    group[0].permissions.add(p)
                for p in djmodel.Permission.objects.filter(codename__in=olds - news):
                    group[0].permissions.remove(p)
                if models.WebGroup.objects.exclude(name=name).filter(name_zh=name_zh).exists():
                    return tools.genErrorStatusResponse(error.status_foundDuplicateID)
                if name_zh:
                    group.update(name_zh=name_zh)
                log.username, log.action, log.content = request.user.username, local.log_modifyRolePerms.value, form.cleaned_data
        except Exception as e:
            if default.debug:
                print(f"in the roleUpdateOrCreate create found error {e}")
            return tools.genErrorStatusResponse(error.status_foundDuplicateID)
    tasks.logRecord.delay(log.toJson)
    return tools.genErrorStatusResponse(error.status_200)


def roleDelete(request):
    form = requestForms.RoleDelete(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    name = form.cleaned_data['name']
    for g in models.WebGroup.objects.filter(name=name):
        if g.isBasic:
            return tools.genErrorStatusResponse(error.status_notAllowed)
        g.isActive = False if g.isActive else True
        g.save()
        log = tools.BaseData()
        log.username, log.action, log.content = request.user.username, local.log_deleteRole.value, name
        tasks.logRecord.delay(log.toJson)
        return tools.genErrorStatusResponse(error.status_200)
    return tools.genErrorStatusResponse(error.status_notFound)


@dbRouter.in_database("subordinate")
def userLists(request):
    """
        获取用户列表
    :param request:
    :return:
    """

    @lru_cache(maxsize=100)
    def users(parentid):
        user_list = []
        mx = max(default.belongs.keys())
        for d in models.District.objects.prefetch_related('webuser_set').filter(ora_parent=parentid).order_by(
                'webuser__createTime').iterator():
            for u in d.webuser_set.all().order_by('createTime').iterator():
                user_list.append(u)
            if d.ora_level >= mx:
                continue
            for item in users(d.ora_index):
                user_list.append(item)
        return user_list

    def users2(parent):
        data = models.WebUser.objects.filter(locate__ora_level__lt=parent)
        return data

    form = requestForms.Page(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    page, size = form.cleaned_data['page'], form.cleaned_data['size']
    try:
        slice_ = tools.getPageSlice(size, page)
    except Exception:
        return tools.genErrorStatusResponse(error.status_checkValueError)
    ds = []
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        total = models.WebUser.objects.exclude(
            Q(username=default.superName) | Q(username=request.user.username)).count()
        for user in \
                models.WebUser.objects.exclude(
                    Q(username=default.superName) | Q(username=request.user.username)).order_by('createTime')[
                    slice_].__iter__():
            dt = tools.BaseData()
            dt.username, dt.name_zh, dt.role, dt.role_zh, dt.isActive = user.username, user.last_name, \
                                                                        user.groups.all()[0].name, user.groups.all()[
                                                                            0].name_zh, 1 if user.is_active else 0
            dt.belong = ' '.join([*reversed(getBelong(user.locate.ora_index))]) if user.locate else None
            dt.belongid = [*reversed(getBelong(user.locate.ora_index, onlyIndex=True)), ] if user.locate else None
            dt.phone = user.phone
            dt.email = user.email
            dt.genre = user.groups.all()[0].genre
            ds.append(dt.toJson)
    else:
        genre_sets = set()
        found = False
        for key in menus.funcs:
            if found:
                genre_sets.add(key.name)
                continue
            if key.name == genre:
                genre_sets.add(key.name)
                found = True
                continue
        query = Q()
        if genre in {local.countyAdmin.name, }:
            query &= Q(groups__genre__in=genre_sets)
        else:
            query &= Q(groups__genre__in=genre_sets) & Q(locate__ora_index=request.user.locate.ora_index)
        total = models.WebUser.objects.exclude(Q(username=request.user.username)).filter(query).count()
        for user in \
                models.WebUser.objects.exclude(Q(username=request.user.username)).filter(query).order_by('createTime')[
                    slice_].__iter__():
            dt = tools.BaseData()
            dt.username, dt.name_zh, dt.role, dt.role_zh, dt.isActive = user.username, user.last_name, \
                                                                        user.groups.all()[0].name, user.groups.all()[
                                                                            0].name_zh, 1 if user.is_active else 0
            dt.belong = ' '.join([*reversed(getBelong(user.locate.ora_index))]) if user.locate else None
            dt.belongid = [*reversed(getBelong(user.locate.ora_index, onlyIndex=True)), ] if user.locate else None
            dt.phone = user.phone
            dt.email = user.email
            dt.genre = user.groups.all()[0].genre
            ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds, **{'total': total})


@dbRouter.in_database('subordinate')
def getUserRoles(request):
    """
        创建用户,角色获取
    :param request:
    :return:
    """
    ds = []
    exclude_set = menus.roles.keys()
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        for r in models.WebGroup.objects.exclude(name__in=exclude_set).filter(isActive=True).order_by('createTime'):
            dt = tools.BaseData()
            dt.genre = r.genre
            dt.name = r.name
            dt.name_zh = r.name_zh
            ds.append(dt.toJson)
    else:
        for r in request.user.groups.all():
            genre = r.genre
            found = False
            for i in menus.roles:
                if found or i == genre:
                    for g in models.WebGroup.objects.exclude(name__in=exclude_set).filter(
                            Q(genre=i) & Q(isActive=True)).order_by('createTime'):
                        dt = tools.BaseData()
                        dt.genre = g.genre
                        dt.name_zh = g.name_zh
                        dt.name = g.name
                        ds.append(dt.toJson)
                    found = True
    return tools.genErrorStatusResponse(error.status_200, ds)


def getBelong(locationid=0, onlyIndex=False):
    """
        递归获取 name到丰台区截至
    :param locationid: 地区id
    :return:
    """
    district_list = []
    for obj in models.District.objects.filter(ora_index=locationid):
        if onlyIndex:
            district_list.append(obj.ora_index)
        else:
            district_list.append(obj.ora_name)
        if obj.ora_index == default.defaultDetailLocations[0]:
            return district_list
        for i in getBelong(obj.ora_parent, onlyIndex).__iter__():
            district_list.append(i)
    return district_list


def updateOrCreateUser(request, created=False):
    form = requestForms.UserUpdateOrCreate(QueryDict(request.body))
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    username, password, name_zh, role, belong, phone, email, isActive = form.cleaned_data['username'], \
                                                                        form.cleaned_data['password'], \
                                                                        form.cleaned_data['name_zh'], form.cleaned_data[
                                                                            'role'], \
                                                                        form.cleaned_data['belong'], form.cleaned_data[
                                                                            'phone'], \
                                                                        form.cleaned_data['email'], form.cleaned_data[
                                                                            'isActive']
    if isActive not in {1, 0}:
        return tools.genErrorStatusResponse(error.status_checkValueError)
    # if phone:
    #     if not tools.checkPhone(phone):
    #         return tools.genErrorStatusResponse(error.status_checkValueError)
    # if email:
    #     if not tools.checkEmail(email):
    #         return tools.genErrorStatusResponse(error.status_checkValueError)
    log = tools.BaseData()

    if created:
        if not password:
            return tools.genErrorStatusResponse(error.status_checkValueError)
        try:
            if models.WebUser.objects.filter(username=username).exists():
                return tools.genErrorStatusResponse(error.status_foundDuplicateID)
            with transaction.atomic():
                user = models.WebUser.objects.create(username=username, last_name=name_zh, phone=phone, email=email,
                                                     is_active=isActive,
                                                     password=make_password(password),
                                                     createTime=make_aware(datetime.datetime.now()))
                for group in models.WebGroup.objects.filter(name=role):
                    user.groups.add(group)
                    if group.genre not in {local.super.name, local.systemAdmin.name}:
                        if not models.District.objects.filter(ora_index=belong).exists():
                            raise Exception("the belong not set properly for user")
                    else:
                        if belong:
                            raise Exception("systeAdmin or super user dont have user locate")
                    for locate in models.District.objects.filter(ora_index=belong):
                        if group.genre in {local.countyAdmin.name, }:
                            if locate.ora_level != 2:
                                raise Exception("error user locate level")
                        elif group.genre in {local.streetAdmin.name, }:
                            if locate.ora_level != 3:
                                raise Exception("error user locate level")
                        user.locate = locate
                        user.save()
                log.username, log.action, log.content = request.user.username, local.log_addUser.value, str(
                    request.body)
        except Exception as e:
            if default.debug:
                print(f"in the updateOrCreateUser create user found error {e}")
            return tools.genErrorStatusResponse(error.status_foundError)
    else:
        try:
            with transaction.atomic():
                for user in models.WebUser.objects.filter(username=username):
                    if phone:
                        user.phone = phone
                    if email:
                        user.email = email
                    user.is_active = isActive
                    if name_zh:
                        user.last_name = name_zh
                    if password:
                        user.password = make_password(password)
                    if role in menus.roles:
                        return tools.genErrorStatusResponse(error.status_checkValueError)
                    for group in user.groups.all():
                        if group.name != role:
                            user.groups.remove(group)
                            for g in models.WebGroup.objects.filter(name=role):
                                user.groups.add(g)
                    genre = user.groups.all()[0].genre
                    if genre in {local.super.name, local.systemAdmin.name}:
                        if belong:
                            return tools.genErrorStatusResponse(error.status_checkValueError)
                        user.locate = None
                    else:
                        district = models.District.objects.get(ora_index=belong)
                        if genre in {local.countyAdmin.name, }:
                            # 区级
                            if district.ora_level != 2:
                                return tools.genErrorStatusResponse(error.status_checkValueError)
                        elif genre in {local.streetAdmin.name, }:
                            # 街道级
                            if district.ora_level != 3:
                                return tools.genErrorStatusResponse(error.status_checkValueError)
                        user.locate = district
                    user.save()
                    break
                else:
                    return tools.genErrorStatusResponse(error.status_notFound)
                log.username, log.action, log.content = request.user.username, local.log_modifyUser.value, str(
                    request.body)
        except Exception as e:
            if default.debug:
                print(f"in the updateOrCreateUser update user found error {e}")
            return tools.genErrorStatusResponse(error.status_foundError)
    tasks.logRecord.delay(log.toJson)
    return tools.genErrorStatusResponse(error.status_200)


def deleteUser(request):
    form = requestForms.UserDelete(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    username = form.cleaned_data['username']
    if username == default.superName:
        return tools.genErrorStatusResponse(error.status_unAuthorized)
    rows = models.WebUser.objects.filter(username=username).delete()
    if not rows:
        return tools.genErrorStatusResponse(error.status_notFound)
    log = tools.BaseData()
    log.username, log.action, log.content = request.user.username, local.log_deleteUser.value, username
    tasks.logRecord.delay(log.toJson)
    return tools.genErrorStatusResponse(error.status_200)


@dbRouter.in_database('subordinate')
def personalInfo(request):
    dt = tools.BaseData()
    dt.username, dt.name_zh, dt.phone, dt.email = request.user.username, request.user.last_name, request.user.phone, request.user.email
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        dt.belong = None
        dt.role = request.user.groups.all()[0].name_zh
    else:
        for group in request.user.groups.all().iterator():
            dt.role = group.name_zh
        dt.belong = ' '.join([*reversed(getBelong(request.user.locate.ora_index))]) if request.user.locate else None
    return tools.genErrorStatusResponse(error.status_200, **dt.toJson)


def modifyMyInfo(request):
    form = requestForms.ModifyMyBasic(QueryDict(request.body))
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    name, phone, email = form.cleaned_data['name'], form.cleaned_data['phone'], form.cleaned_data['email']
    rows = models.WebUser.objects.filter(username=request.user.username).update(last_name=name, phone=phone,
                                                                                email=email)
    if not rows:
        return tools.genErrorStatusResponse(error.status_notFound)
    return tools.genErrorStatusResponse(error.status_200)


def updatePassword(request):
    form = requestForms.ChangePassword(QueryDict(request.body))
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    password = form.cleaned_data['password']
    originPwd = form.cleaned_data['originPwd']
    # if request.user.is_superuser:
    #     return tools.genErrorStatusResponse(error.status_unAuthorized)
    if not check_password(originPwd, request.user.password):
        return tools.genErrorStatusResponse(error.status_checkValueError)
    request.user.password = make_password(password)
    request.user.save()
    log = tools.BaseData()
    log.username, log.action, log.content = request.user.username, local.log_changePassword.value, password
    tasks.logRecord.delay(log.toJson)
    return tools.genErrorStatusResponse(error.status_200)


@dbRouter.in_database('subordinate')
def logList(request):
    form = requestForms.Page(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    page, size = form.cleaned_data['page'], form.cleaned_data['size']
    slice_ = tools.getPageSlice(size, page)
    total = models.Log.objects.count()
    ds = []
    for item in models.Log.objects.order_by('-createTime')[slice_]:
        dt = tools.BaseData()
        dt.id, dt.createTime, dt.username, dt.name_zh, dt.action = item.id, item.createTime.strftime(
            '%Y-%m-%d %H:%M'), item.username, \
                                                                   item.name, item.action
        # dt.content = item.content if item.content else ''
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds, **{'total': total})


@dbRouter.in_database('subordinate')
def detailLog(request):
    form = requestForms.IDForm(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    id_ = form.cleaned_data['id']
    for item in models.Log.objects.filter(id=id_):
        dt = tools.BaseData()
        dt.id, dt.createTime, dt.username, dt.name_zh, dt.action = item.id, item.createTime.strftime(
            '%Y-%m-%d %H:%M'), item.username, \
                                                                   item.name, item.action
        dt.content = item.content if item.content else ''
        return tools.genErrorStatusResponse(error.status_200, dt.toJson)
    else:
        return tools.genErrorStatusResponse(error.status_notFound)


@dbRouter.in_database('subordinate')
def logDynamicSearch(request):
    """
        系统日志动态搜索
    :param request:
    :return:
    """
    form = requestForms.LogDynamic(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    date = form.cleaned_data['date']
    username = form.cleaned_data['username']
    size = form.cleaned_data['size']
    page = form.cleaned_data['page']
    query = Q()
    try:
        if date:
            st, ed = (*map(lambda x: datetime.datetime.strptime(x, '%Y-%m-%d'), date.split(";")),)
            # 三个月时间的设置
            if 0 <= (ed - st).total_seconds():
                pass
            else:
                raise Exception("time set error")
            query = Q(createTime__gte=make_aware(st)) & Q(
                createTime__lte=make_aware(ed + relativedelta.relativedelta(days=1)))
        slice_ = tools.getPageSlice(size, page)
    except Exception as e:
        if default.debug:
            print(f"in the logDynamicSearch found parse date error")
        return tools.genErrorStatusResponse(error.status_checkValueError)

    if username:
        query &= Q(username__regex=username)
    ds: list = []
    total = models.Log.objects.filter(query).count()
    for item in \
            models.Log.objects.filter(query).values('id', 'createTime', 'name', 'action', 'username').order_by(
                '-createTime')[
                slice_]:
        dt = tools.BaseData()
        dt.id, dt.createTime, dt.username, dt.name_zh, dt.action = item['id'], (item['createTime']).strftime(
            '%Y-%m-%d %H:%M'), item['username'], item['name'], item['action']
        # dt.content = item.content if item.content else ''
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds, **{'total': total})


@dbRouter.in_database("subordinate")
def getAllStreets2(request):
    """
        获取所有的街道
    :param request:
    :return:
    """
    ds = []
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        dt = tools.BaseData()
        dt.name = "全部"
        dt.id = None
        dt.level = None
        ds.append(dt.toJson)
        for it in models.District.objects.filter(
                Q(ora_parent=default.defaultDetailLocations[0]) & Q(ora_status=1)).order_by('-ora_weight').iterator():
            dt = tools.BaseData()
            dt.name = it.ora_name
            dt.id = it.ora_index
            dt.level = it.ora_level
            ds.append(dt.toJson)
        dt = tools.BaseData()
        dt.name, dt.id, dt.level = default.defaultNoneString, default.defaulNoneInt, None
        ds.append(dt.toJson)
    else:
        if genre in {local.countyAdmin.name, }:
            dt = tools.BaseData()
            dt.name = "全部"
            dt.id = default.defaultDetailLocations[0]
            dt.level = None
            ds.append(dt.toJson)
            for it in models.District.objects.filter(
                    Q(ora_parent=default.defaultDetailLocations[0]) & Q(ora_status=1)).order_by(
                '-ora_weight').iterator():
                dt = tools.BaseData()
                dt.name = it.ora_name
                dt.id = it.ora_index
                dt.level = it.ora_level
                ds.append(dt.toJson)
            dt = tools.BaseData()
            dt.name, dt.id, dt.level = default.defaultNoneString, default.defaulNoneInt, None
            ds.append(dt.toJson)
        elif genre == local.streetAdmin.name:
            dt = tools.BaseData()
            dt.name = "全部"
            dt.id = request.user.locate.ora_index
            dt.level = None
            ds.append(dt.toJson)
            for it in models.District.objects.filter(
                    Q(ora_index=request.user.locate.ora_index) & Q(ora_status=1)).order_by('-ora_weight').iterator():
                dt = tools.BaseData()
                dt.name = it.ora_name
                dt.id = it.ora_index
                dt.level = it.ora_level
                ds.append(dt.toJson)
    return ds


@dbRouter.in_database('subordinate')
def getAllCommunites(request):
    """
        获取街道下的社区
    :param request:
    :return:
    """
    form = requestForms.IDForm(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    id_ = form.cleaned_data['id']
    ds = []
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        for it in models.District.objects.filter(Q(ora_parent=id_) & Q(ora_status=1)).order_by(
                '-ora_weight').iterator():
            if it.ora_level != 4:
                return tools.genErrorStatusResponse(error.status_notAllowed)
            dt = tools.BaseData()
            dt.name = it.ora_name
            dt.level = it.ora_level
            dt.id = it.ora_index
            ds.append(dt.toJson)
    else:
        # 区级及以上的
        for it in models.District.objects.filter(Q(ora_parent=id_) & Q(ora_status=1)).order_by(
                '-ora_weight').iterator():
            if it.ora_level != 4:
                return tools.genErrorStatusResponse(error.status_notAllowed)
            dt = tools.BaseData()
            dt.name = it.ora_name
            dt.id = it.ora_index
            dt.level = it.ora_level
            ds.append(dt.toJson)
    ds.insert(0, {"name": "全部", "id": None, "level": 4})
    dt = tools.BaseData()
    dt.name, dt.id = default.defaultNoneString, default.defaulNoneInt
    ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds)


def olderConditions(request):
    """
        查询条件
    :param request:
    :return:
    """
    keys = [
        'locateAll',
        'isObjectServiced',
        'identityCard',
        "birthDay",
        "name",
        "gender",
        "isDeath",
        "nationality",
        "education",
        "politics",
        "marriageStatus",
        "identityType",
        "address",
        "postcode",
        "censusRegister",
        "registerNature",
        "emergencyPeople",
        "emergencyPhone",
        "telephone",
        "mobilephone",
        "bjtCard",
        "bankCard",
        "insuranceType",
        "medicalInsuranceType",
        "insured",
        "mininumLivingLevel",
        "laborCapacity",
        "employmentStatus",
        "vocation",
        "healthStatus",
        "bodyStatus",
        "residenceStatus",
        "livingDegree",
        "careType",
        "economicSource",
        "incomingLevel",
        "homeOwnership",
        "isRetire",
        "isObjectTraditional",
        "isSpecialSalvation",
        "isLonely",
        "isDisabled",
        "isNZJ",
        "isReleased",
        "isExservicee",
        "isReservoirImmigrant",
        "isAbroadRelative",
    ]

    ds = []
    for index, it in enumerate(keys):
        dt = tools.BaseData()
        atr = "param_{}".format(it)
        dt.name = getattr(local, atr).value
        dt.codename = it
        # 前端要求添加
        if index <= 3:
            dt.status = 1
        else:
            dt.status = 0
        dt.conditions = []
        if it == 'locateAll':
            dt.conditions = getAllStreets2(request)
        elif it == 'isDeath':
            for k, v in getattr(default, it).items():
                # 未定义的先取掉
                if k == 3:
                    continue
                x = tools.BaseData()
                x.key = v
                x.value = k
                dt.conditions.append(x.toJson)
            o = tools.BaseData()
            o.key = "全部"
            o.value = None
            dt.status = 1
            dt.conditions.append(o.toJson)
        else:
            if getattr(default, it, None):
                o = tools.BaseData()
                o.key = "全部"
                o.value = None
                dt.conditions.append(o.toJson)
                for k, v in getattr(default, it).items():
                    x = tools.BaseData()
                    x.key = v
                    x.value = k
                    dt.conditions.append(x.toJson)
        if not dt.conditions:
            delattr(dt, 'conditions')
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds)


def makeQuery(request, baseForm=None):
    """
        老人信息查询基础处理方法
    :param request:
    :param baseForm:
    :return:
    """

    def checkid(atr, val):
        for k, v in getattr(default, atr).items():
            if k == val:
                return True
        return False

    keys = [
        "isObjectServiced",
        "identityCard",
        "birthDay",
        "name",
        "gender",
        "isDeath",
        "nationality",
        "education",
        "politics",
        "marriageStatus",
        "identityType",
        "address",
        "locate_county",
        "locate_street",
        "locate_community",
        "postcode",
        "censusRegister",
        "registerNature",
        "emergencyPeople",
        "emergencyPhone",
        "telephone",
        "mobilephone",
        "bjtCard",
        "bankCard",
        "insuranceType",
        "medicalInsuranceType",
        "insured",
        "mininumLivingLevel",
        "laborCapacity",
        "employmentStatus",
        "vocation",
        "healthStatus",
        "bodyStatus",
        "residenceStatus",
        "livingDegree",
        "careType",
        "economicSource",
        "incomingLevel",
        'homeOwnership',
        "isObjectTraditional",
        "isSpecialSalvation",
        "isLonely",
        "isDisabled",
        "isNZJ",
        "isReleased",
        "isExservicee",
        "isReservoirImmigrant",
        "isAbroadRelative",
        "isRetire",
        'page',
        'size',
        'user_genre',
        'locate_ora_index'
    ]
    try:
        form = namedtuple('tmp', keys)(**baseForm)
    except Exception as e:
        if default.debug:
            print(f"in the makeQuery found  form error {baseForm}  {e}")
        return None, None
    street_ids = set()
    community_ids = set()
    county_ids = set()

    for key in keys:
        val = getattr(form, key)
        if val:
            try:
                if val not in getattr(default, key):
                    return None, form
            except AttributeError:
                continue
    # 默认丰台区的id
    # county_ids.add(default.defaultDetailLocations[0])
    if form.locate_street:
        street_ids.add(form.locate_street)
    else:
        if form.user_genre in {local.systemAdmin.name, local.countyAdmin.name, local.super.name}:
            pass
        elif form.user_genre in {local.streetAdmin.name, }:
            street_ids.add(form.locate_ora_index)
        # 有街道再添加街道....
    if form.locate_community:
        community_ids.add(form.locate_community)

    query = Q()
    if county_ids:
        query &= Q(locate_county__ora_index__in=county_ids)
    if street_ids:
        if default.defaulNoneInt in street_ids:
            query &= Q(locate_street=None)
        else:
            query &= Q(locate_street__ora_index__in=street_ids)
    if community_ids:
        if default.defaulNoneInt in community_ids:
            query &= Q(locate_community=None)
        else:
            query &= Q(locate_community__ora_index__in=community_ids)
    # pensions
    if form.bjtCard:
        query &= Q(pensions__bjtCard=form.bjtCard)
    if form.bankCard:
        query &= Q(pensions__bankCard=form.bankCard)
    if form.insuranceType:
        if not checkid('insuranceType', form.insuranceType):
            return None, form
        query &= Q(pensions__insuranceType=form.insuranceType)
    if form.medicalInsuranceType:
        if not checkid('medicalInsuranceType', form.medicalInsuranceType):
            return None, form
        query &= Q(pensions__medicalInsuranceType=form.medicalInsuranceType)
    if form.insured:
        if not checkid('insured', form.insured):
            return None, form
        query &= Q(pensions__insured=form.insured)
    if form.mininumLivingLevel:
        if not checkid('mininumLivingLevel', form.mininumLivingLevel):
            return None, form
        query &= Q(pensions__mininumLivingLevel=form.mininumLivingLevel)
    if form.laborCapacity:
        if not checkid('laborCapacity', form.laborCapacity):
            return None, form
        query &= Q(pensions__laborCapacity=form.laborCapacity)
    if form.bodyStatus:
        if not checkid('bodyStatus', form.bodyStatus):
            return None, form
        query &= Q(pensions__bodyStatus=form.bodyStatus)
    if form.employmentStatus:
        if not checkid('employmentStatus', form.employmentStatus):
            return None, form
        query &= Q(pensions__employmentStatus=form.employmentStatus)
    if form.vocation:
        if not checkid('vocation', form.vocation):
            return None, form
        query &= Q(pensions__vocation=form.vocation)
    if form.healthStatus:
        if not checkid('healthStatus', form.healthStatus):
            return None, form
        query &= Q(pensions__healthStatus=form.healthStatus)
    if form.residenceStatus:
        if not checkid('residenceStatus', form.residenceStatus):
            return None, form
        query &= Q(pensions__residenceStatus=form.residenceStatus)
    if form.livingDegree:
        if not checkid('livingDegree', form.livingDegree):
            return None, form
        query &= Q(pensions__livingDegree=form.livingDegree)
    if form.careType:
        if not checkid('careType', form.careType):
            return None, form
        query &= Q(pensions__careType=form.careType)
    if form.economicSource:
        if not checkid('economicSource', form.economicSource):
            return None, form
        query &= Q(pensions__economicSource=form.economicSource)
    if form.incomingLevel:
        if not checkid('incomingLevel', form.incomingLevel):
            return None, form
        query &= Q(pensions__incomingLevel=form.incomingLevel)

    if form.homeOwnership:
        if not checkid('homeOwnership', form.homeOwnership):
            return None, form
        query &= Q(pensions__homeOwnership=form.homeOwnership)

    # flag
    if form.isObjectServiced:
        if not checkid('isObjectServiced', form.isObjectServiced):
            return None, form
        query &= Q(flag__isObjectServiced=form.isObjectServiced)
    if form.isObjectTraditional:
        if not checkid('isObjectTraditional', form.isObjectTraditional):
            return None, form
        query &= Q(flag__isObjectTraditional=form.isObjectTraditional)
    if form.isSpecialSalvation:
        if not checkid('isSpecialSalvation', form.isSpecialSalvation):
            return None, form
        query &= Q(flag__isSpecialSalvation=form.isSpecialSalvation)
    if form.isLonely:
        if not checkid('isLonely', form.isLonely):
            return None, form
        query &= Q(flag__isLonely=form.isLonely)
    if form.isNZJ:
        if not checkid('isNZJ', form.isNZJ):
            return None, form
        query &= Q(flag__isNZJ=form.isNZJ)
    if form.isReleased:
        if not checkid('isReleased', form.isReleased):
            return None, form
        query &= Q(flag__isReleased=form.isReleased)
    if form.isExservicee:
        if not checkid('isExservicee', form.isExservicee):
            return None, form
        query &= Q(flag__isExservicee=form.isExservicee)
    if form.isReservoirImmigrant:
        if not checkid('isReservoirImmigrant', form.isReservoirImmigrant):
            return None, form
        query &= Q(flag__isReservoirImmigrant=form.isReservoirImmigrant)
    if form.isAbroadRelative:
        if not checkid('isAbroadRelative', form.isAbroadRelative):
            return None, form
        query &= Q(flag__isAbroadRelative=form.isAbroadRelative)
    if form.isDeath:
        if not checkid('isDeath', form.isDeath):
            return None, form
        # query &= Q(flag__isDeath=form.isDeath)
        # 活着的,正常的
        if form.isDeath == 1:
            query &= Q(flag__isDeath__in={1, 3})
        else:
            query &= Q(flag__isDeath=form.isDeath)
    if form.isDisabled:
        if not checkid('isDisabled', form.isDisabled):
            return None, form
        query &= Q(flag__isDisabled=form.isDisabled)
    if form.isRetire:
        if not checkid('isRetire', form.isRetire):
            return None, form
        query &= Q(flag__isRetire=form.isRetire)

    # main
    if form.identityCard:
        query &= Q(identityCard=form.identityCard)
    if form.gender:
        if not checkid('gender', form.gender):
            return None, form
        query &= Q(gender=form.gender)
    if form.name:
        query &= Q(name__regex=form.name)
    if form.birthDay:
        # 查询的老人都是60岁以上的
        try:
            start, end = form.birthDay.split(';')
            now = datetime.datetime.now().strftime('%Y-%m-%d')
            # 取消60岁的限制
            # years_60 = datetime.datetime.strptime(now, '%Y-%m-%d') - relativedelta.relativedelta(years=60)
            start, end = datetime.datetime.strptime(start, '%Y-%m-%d'), datetime.datetime.strptime(end, '%Y-%m-%d')
            if (end - start).total_seconds() < 0:
                raise Exception("end time less than start")
            # if (end - years_60).total_seconds() > 0:
            #     end = years_60
            # if (start - years_60).total_seconds() > 0:
            #     # 直接返回空的数据
            #     start, end = datetime.datetime.strptime(now, '%Y-%m-%d'), datetime.datetime.strptime(now, '%Y-%m-%d')
            query &= Q(birthDay__gte=make_aware(start))
            query &= Q(birthDay__lte=make_aware(end))
        except Exception as e:
            if default.debug:
                print(f"in the makeQuery fun start,end time error {e}")
            return None, form
    else:
        # now = datetime.datetime.now().strftime('%Y-%m-%d')
        # years_60 = datetime.datetime.strptime(now, '%Y-%m-%d') - relativedelta.relativedelta(years=60)
        # query &= Q(birthDay__lte=make_aware(years_60))
        pass

    if form.nationality:
        if not checkid('nationality', form.nationality):
            return None, form
        query &= Q(nationality=form.nationality)
    if form.education:
        if not checkid('education', form.education):
            return None, form
        query &= Q(education=form.education)
    if form.politics:
        if not checkid('politics', form.politics):
            return None, form
        query &= Q(politics=form.politics)
    if form.marriageStatus:
        if not checkid('marriageStatus', form.marriageStatus):
            return None, form
        query &= Q(marriageStatus=form.marriageStatus)
    if form.identityType:
        if not checkid('identityType', form.identityType):
            return None, form
        query &= Q(identityType=form.identityType)
    if form.address:
        query &= Q(address__regex=form.address)
    if form.censusRegister:
        query &= Q(censusRegister__regex=form.censusRegister)
    if form.postcode:
        query &= Q(postcode=form.postcode)
    if form.registerNature:
        if not checkid('registerNature', form.registerNature):
            return None, form
        query &= Q(registerNature=form.registerNature)
    if form.emergencyPeople:
        query &= Q(emergencyPeople__regex=form.emergencyPeople)
    if form.emergencyPhone:
        query &= Q(emergencyPhone__regex=form.emergencyPhone)
    if form.telephone:
        query &= Q(telephone__regex=form.telephone)
    if form.mobilephone:
        query &= Q(mobilephone__regex=form.mobilephone)
    return query, form


@dbRouter.in_database('subordinate')
def genderAndPolitics_statistic(request):
    """
        性别与政治面貌统计
    :param request:
    :return:
    """
    form = requestForms.OlderInfo(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    genre = request.user.groups.all()[0].genre
    form.cleaned_data['user_genre'] = request.user.groups.all()[0].genre
    form.cleaned_data['locate_ora_index'] = request.user.locate.ora_index if genre not in {local.super.name,
                                                                                           local.systemAdmin.name} else None
    baseForm = form
    query, form = makeQuery(request, form.cleaned_data)
    # if not query:
    #     return tools.genErrorStatusResponse(error.status_checkValueError)
    key = "{}_genderAndPolitics_{}".format(models.BasicInfoOfOlder.__name__, tools.getMD5(str(query)))
    lock = "genderAndPolitics_{}".format(key)
    proxy = tools.CacheProxy(key=key)
    if proxy.hasKey():
        return tools.genErrorStatusResponse(error.status_200, json.loads(proxy.getCache())["data"])
    with cache.lock(lock, timeout=10):
        if proxy.hasKey():
            return tools.genErrorStatusResponse(error.status_200, json.loads(proxy.getCache())["data"])
        tmp: list = []
        for it in models.BasicInfoOfOlder.objects.filter(query).values('gender', 'politics').annotate(
                peo=Count('gender'),
                pos=Count(
                    'politics')).iterator():
            tmp.append(it)
        ds = []
        indice = 0
        for k, v in default.gender.items():
            dt = tools.BaseData()
            dt.total = 0
            dt.gender = v
            dt.codename = string.ascii_letters[indice]
            indice += 1
            dt.politics = []
            nations = {}
            for pk, pv in default.politics.items():
                nations[pv] = 0
            for it in tmp:
                if it['gender'] == k:
                    dt.total += it['peo']
                    if it['politics']:
                        for x, y in default.politics.items():
                            if x == it['politics']:
                                nations[y] += it['pos']
            for index, v in enumerate(nations):
                t = tools.BaseData()
                t.name = v
                t.value = nations[v]
                t.codename = string.ascii_letters[index]
                dt.politics.append(t.toJson)
            ds.append(dt.toJson)
        proxy.setCache(json.dumps({"baseForm": baseForm.cleaned_data, "data": ds}),
                       timeout=default.common_cache_timeout)
        return tools.genErrorStatusResponse(error.status_200, ds)


@dbRouter.in_database('subordinate')
def nationality_statistic(request):
    """
        民族人数统计
    :param request:
    :return:
    """
    form = requestForms.OlderInfo(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    genre = request.user.groups.all()[0].genre
    form.cleaned_data['user_genre'] = request.user.groups.all()[0].genre
    form.cleaned_data['locate_ora_index'] = request.user.locate.ora_index if genre not in {local.super.name,
                                                                                           local.systemAdmin.name} else None
    baseForm = form
    query, form = makeQuery(request, form.cleaned_data)
    # if not query:
    #     return tools.genErrorStatusResponse(error.status_checkValueError)
    key = "{}_nationality_{}".format(models.BasicInfoOfOlder.__name__, tools.getMD5(str(query)))
    lock = "nationality_{}".format(key)
    proxy = tools.CacheProxy(key=key)
    if proxy.hasKey():
        return tools.genErrorStatusResponse(error.status_200, json.loads(proxy.getCache())["data"])
    with cache.lock(lock, timeout=60):
        if proxy.hasKey():
            return tools.genErrorStatusResponse(error.status_200, json.loads(proxy.getCache())["data"])
        ds: list = []
        for it in models.BasicInfoOfOlder.objects.filter(query).values('nationality').annotate(
                mx=Count('nationality')).iterator():
            dt = tools.BaseData()
            if it['nationality']:
                dt.name = default.nationality[it['nationality']]
                dt.value = it['mx']
            ds.append(dt.toJson)
        if not ds:
            ds.append({
                "name": "未定义",
                "value": 0
            })
        proxy.setCache(json.dumps({"baseForm": baseForm.cleaned_data, "data": ds}),
                       timeout=default.common_cache_timeout)
        return tools.genErrorStatusResponse(error.status_200, ds)


@dbRouter.in_database('subordinate')
def peopleOfStreet_statistic(request):
    """
        当前选择范围的各街乡镇人数柱状图
    :param request:
    :return:
    """
    form = requestForms.OlderInfo(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    genre = request.user.groups.all()[0].genre
    form.cleaned_data['user_genre'] = request.user.groups.all()[0].genre
    form.cleaned_data['locate_ora_index'] = request.user.locate.ora_index if genre not in {local.super.name,
                                                                                           local.systemAdmin.name} else None
    baseForm = form
    query, form = makeQuery(request, form.cleaned_data)

    # if not query:
    #     return tools.genErrorStatusResponse(error.status_checkValueError)
    key = "{}_peopleOfStreet_{}".format(models.BasicInfoOfOlder.__name__, tools.getMD5(str(query)))
    lock = "peopleOfStreet_{}".format(key)
    proxy = tools.CacheProxy(key=key)
    if proxy.hasKey():
        return tools.genErrorStatusResponse(error.status_200, json.loads(proxy.getCache())["data"])
    with cache.lock(lock, timeout=60):
        if proxy.hasKey():
            return tools.genErrorStatusResponse(error.status_200, json.loads(proxy.getCache())["data"])
        street_name: list = []
        street_number: list = []
        for it in models.BasicInfoOfOlder.objects.filter(query).values('locate_street__ora_name').annotate(
                mx=Count('locate_street')).iterator():
            if it['locate_street__ora_name']:
                street_name.append(it['locate_street__ora_name'])
                street_number.append(it['mx'])
        dt = tools.BaseData()
        dt.name = street_name if street_name else ["未定义", ]
        dt.count = street_number if street_number else [0, ]
        proxy.setCache(json.dumps({"baseForm": baseForm.cleaned_data, "data": dt.toJson}),
                       timeout=default.common_cache_timeout)
        return tools.genErrorStatusResponse(error.status_200, dt.toJson)


@dbRouter.in_database('subordinate')
def peopleOfCommunity_statistic(request):
    """
        各社区人数统计
    :param request:
    :return:
    """
    form = requestForms.OlderInfo(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    genre = request.user.groups.all()[0].genre
    form.cleaned_data['user_genre'] = request.user.groups.all()[0].genre
    form.cleaned_data['locate_ora_index'] = request.user.locate.ora_index if genre not in {local.super.name,
                                                                                           local.systemAdmin.name} else None
    baseForm = form
    query, form = makeQuery(request, form.cleaned_data)
    # if not query:
    #     return tools.genErrorStatusResponse(error.status_checkValueError)

    key = "{}_peopleOfCommunity_{}".format(models.BasicInfoOfOlder.__name__, tools.getMD5(str(query)))
    lock = "peopleOfCommunity_{}".format(key)
    proxy = tools.CacheProxy(key=key)
    if proxy.hasKey():
        return tools.genErrorStatusResponse(error.status_200, json.loads(proxy.getCache())["data"])
    with cache.lock(lock, timeout=60):
        if proxy.hasKey():
            return tools.genErrorStatusResponse(error.status_200, json.loads(proxy.getCache())["data"])
        community_name: list = []
        community_number: list = []
        for it in models.BasicInfoOfOlder.objects.filter(query).values('locate_community__ora_name').annotate(
                mx=Count('locate_community')).iterator():
            if it['locate_community__ora_name']:
                community_name.append(it['locate_community__ora_name'])
                community_number.append(it['mx'])
        dt = tools.BaseData()
        dt.name = community_name if community_name else ["未定义", ]
        dt.count = community_number if community_number else [0, ]
        proxy.setCache(json.dumps({"baseForm": baseForm.cleaned_data, "data": dt.toJson}),
                       timeout=default.common_cache_timeout)
        return tools.genErrorStatusResponse(error.status_200, dt.toJson)


@dbRouter.in_database("subordinate")
def insurance_statistic(request):
    """
        各年龄段保障对象人数统计
    :param request:
    :return:
    """

    form = requestForms.OlderInfo(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    genre = request.user.groups.all()[0].genre
    form.cleaned_data['user_genre'] = request.user.groups.all()[0].genre
    form.cleaned_data['locate_ora_index'] = request.user.locate.ora_index if genre not in {local.super.name,
                                                                                           local.systemAdmin.name} else None
    baseForm = form
    query, form = makeQuery(request, form.cleaned_data)
    # if not query:
    #     return tools.genErrorStatusResponse(error.status_checkValueError)
    key = "{}_insurance_{}".format(models.BasicInfoOfOlder.__name__, tools.getMD5(str(query)))
    lock = "insurance_{}".format(key)
    proxy = tools.CacheProxy(key=key)
    if proxy.hasKey():
        return tools.genErrorStatusResponse(error.status_200, json.loads(proxy.getCache())["data"])
    with cache.lock(lock, timeout=60):
        if proxy.hasKey():
            return tools.genErrorStatusResponse(error.status_200, json.loads(proxy.getCache())["data"])
        now = datetime.datetime.strptime(datetime.datetime.now().strftime('%Y%m%d'), '%Y%m%d')
        date_map = {}
        another_map = {}
        for i in default.ageScope:
            s, e = i
            end = now - dateutil.relativedelta.relativedelta(years=s - 1)
            start = now - dateutil.relativedelta.relativedelta(years=e)
            start_str = int(start.strftime('%Y%m%d'))
            end_str = int(end.strftime("%Y%m%d"))
            key = "{}-{}".format(start_str, end_str)
            date_map[key] = {}
            for x in default.insuranceType:
                date_map[key][x] = 0
            another_map[key] = "{}-{}岁".format(s, e)

        for it in models.BasicInfoOfOlder.objects.filter(query).select_related(
                'pensions').values('birthDay',
                                   'pensions__insuranceType').annotate(
            mx=Count('birthDay')).__iter__():
            if not it['birthDay']:
                continue
            val = it['birthDay'].strftime('%Y%m%d')
            for k in date_map.keys():
                start, end = k.split('-')
                if int(start) <= int(val) < int(end):
                    if it['pensions__insuranceType']:
                        ty = it['pensions__insuranceType']
                        date_map[k][ty] += it['mx']
                        break
        rows = len(date_map)
        columns = len(default.insuranceType)
        array = np.zeros((rows, columns), dtype=int)
        for index, v in enumerate(date_map):
            vd = date_map[v]
            for cindex, vc in enumerate(vd):
                array[index, cindex] = vd[vc]
        dt = tools.BaseData()
        dt.response = []
        for index, k in enumerate(default.insuranceType):
            t = tools.BaseData()
            t.name = default.insuranceType[k]
            t.value = array[:, index].tolist()
            t.codename = string.ascii_letters[index]
            dt.response.append(t.toJson)
        dt.agesType = []
        for k, v in another_map.items():
            dt.agesType.append(v)
        proxy.setCache(json.dumps({"baseForm": baseForm.cleaned_data, "data": dt.toJson}),
                       timeout=default.common_cache_timeout)
        return tools.genErrorStatusResponse(error.status_200, dt.toJson)


@dbRouter.in_database('subordinate')
def olderList(request):
    """
        老人信息列表
    :param request:
    :return:
    """
    form = requestForms.OlderInfo(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    genre = request.user.groups.all()[0].genre
    form.cleaned_data['user_genre'] = genre
    form.cleaned_data['locate_ora_index'] = request.user.locate.ora_index if genre not in {local.super.name,
                                                                                           local.systemAdmin.name} else None
    query, form = makeQuery(request, form.cleaned_data)
    # if not query:
    #     return tools.genErrorStatusResponse(error.status_checkValueError)
    if form.size not in default.defaultPageSize:
        return tools.genErrorStatusResponse(error.status_checkValueError)
    slice_ = tools.getPageSlice(form.size, form.page)
    ds = []
    now = datetime.datetime.now() + datetime.timedelta(days=-1)
    objs = models.BasicInfoOfOlder.objects.prefetch_related('flag', 'pensions').filter(query).values('name', 'gender',
                                                                                                     'identityCard',
                                                                                                     'address',
                                                                                                     'birthDay').order_by(
        'id')
    # 这里访问速度慢,需要缓存
    key = "{}_{}".format(default.edlerCountCacheKey, tools.getMD5(str(query)))
    if key in cache:
        total = cache.get(key)
    else:
        total = objs.count()
        cache.set(key, total)
    for it in objs[slice_]:
        dt = tools.BaseData()
        dt.name = it['name']
        dt.gender = default.gender[it['gender']]
        dt.identityCard = it['identityCard']
        dt.address = it['address']
        if not it['birthDay']:
            dt.age = None
        else:
            dt.age = rrule.rrule(rrule.YEARLY,
                                 dtstart=it['birthDay'],
                                 until=now).count()
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds, **{'total': total})


@dbRouter.in_database('subordinate')
def olderDetail(request):
    """
        老人详细信息
    :param request:
    :return:
    """

    def item(it: models.BasicInfoOfOlder, key, tp=str, foreign=False, foreignKey=None, isLocate=False):
        dt = tools.BaseData()
        if foreign:
            dt.name = getattr(local, "param_{}".format(foreignKey)).value
        else:
            dt.name = getattr(local, "param_{}".format(key)).value
        if foreign:
            dt.codename = foreignKey
        else:
            dt.codename = key
        if foreign:
            if getattr(it, key, None):
                if tp == str:
                    dt.value = getattr(getattr(it, key), foreignKey)
                elif tp == int:
                    if isLocate:
                        dt.value = getattr(getattr(it, key), 'ora_name')
                    else:
                        dt.value = getattr(default, foreignKey)[getattr(getattr(it, key), foreignKey)] if getattr(
                            getattr(it, key),
                            foreignKey,
                            None) else None
            else:
                dt.value = None
        else:
            if tp == str:
                dt.value = getattr(it, key)
            elif tp == int:
                dt.value = getattr(default, key)[getattr(it, key)] if getattr(it, key, None) else None
            elif tp == time:
                dt.value = getattr(it, key).strftime('%Y-%m-%d') if getattr(it, key, None) else None
        return dt.toJson

    form = requestForms.OlderDetail(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    identityCard = form.cleaned_data['identityCard']
    ds = []
    for it in models.BasicInfoOfOlder.objects.select_related('flag', 'pensions', 'locate_street', 'locate_community',
                                                             'locate_county').filter(identityCard=identityCard):
        dt = tools.BaseData()
        dt.name = "必填信息"
        dt.codename = 'a'
        dt.sub = []
        dt.sub.append(item(it, 'name'))
        dt.sub.append(item(it, 'gender', tp=int))
        dt.sub.append(item(it, 'identityCard'))
        dt.sub.append(item(it, 'birthDay', tp=time))
        dt.sub.append(item(it, 'flag', foreign=True, tp=int, foreignKey='isDeath'))
        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "个人信息"
        dt.codename = 'b'
        dt.sub = []
        dt.sub.append(item(it, 'nationality', tp=int))
        dt.sub.append(item(it, 'education', tp=int))
        dt.sub.append(item(it, 'identityType', tp=int))
        dt.sub.append(item(it, 'marriageStatus', tp=int))
        dt.sub.append(item(it, 'politics', tp=int))
        dt.sub.append(item(it, 'telephone'))
        dt.sub.append(item(it, 'mobilephone'))

        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "位置信息"
        dt.codename = "c"
        dt.sub = []
        x = tools.BaseData()
        x.name = "所在地区"
        x.codename = "locate"
        x.value = ' '.join([*filter(lambda x: x if x else 0, [
            item(it, 'locate_county', tp=int, foreign=True, foreignKey='locate_county', isLocate=True)['value'],
            item(it, 'locate_street', tp=int, foreign=True, foreignKey='locate_street', isLocate=True)['value'],
            item(it, 'locate_community', tp=int, foreign=True, foreignKey='locate_community', isLocate=True)['value']
        ]), ])
        dt.sub.append(x.toJson)
        dt.sub.append(item(it, 'address'))
        dt.sub.append(item(it, 'censusRegister'))
        dt.sub.append(item(it, 'registerNature', tp=int))
        dt.sub.append(item(it, 'postcode'))
        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "紧急联系人信息"
        dt.codename = "d"
        dt.sub = []
        dt.sub.append(item(it, 'emergencyPeople'))
        dt.sub.append(item(it, 'emergencyPhone'))
        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "养老信息"
        dt.codename = "e"
        dt.sub = []
        dt.sub.append(item(it, 'pensions', foreignKey='bjtCard', foreign=True))
        dt.sub.append(item(it, 'pensions', foreign=True, foreignKey='bankCard'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='incomingLevel'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='economicSource'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='careType'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='livingDegree'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='residenceStatus'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='healthStatus'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='vocation'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='employmentStatus'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='bodyStatus'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='laborCapacity'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='mininumLivingLevel'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='insured'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='medicalInsuranceType'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='insuranceType'))
        dt.sub.append(item(it, 'pensions', foreign=True, tp=int, foreignKey='homeOwnership'))
        dt.sub.append(item(it, 'flag', foreign=True, tp=int, foreignKey='isRetire'))

        dt.sub.append(item(it, 'flag', foreign=True, tp=int, foreignKey='isAbroadRelative'))
        dt.sub.append(item(it, 'flag', foreign=True, tp=int, foreignKey='isReservoirImmigrant'))
        dt.sub.append(item(it, 'flag', foreign=True, tp=int, foreignKey='isExservicee'))
        dt.sub.append(item(it, 'flag', foreign=True, tp=int, foreignKey='isReleased'))
        dt.sub.append(item(it, 'flag', foreign=True, tp=int, foreignKey='isNZJ'))
        dt.sub.append(item(it, 'flag', foreign=True, tp=int, foreignKey='isDisabled'))
        dt.sub.append(item(it, 'flag', foreign=True, tp=int, foreignKey='isLonely'))
        dt.sub.append(item(it, 'flag', foreign=True, tp=int, foreignKey='isSpecialSalvation'))
        dt.sub.append(item(it, 'flag', foreign=True, tp=int, foreignKey='isObjectTraditional'))
        dt.sub.append(item(it, 'flag', foreign=True, tp=int, foreignKey='isObjectServiced'))

        ds.append(dt.toJson)
        return tools.genErrorStatusResponse(error.status_200, ds)
    return tools.genErrorStatusResponse(error.status_notFound)


@dbRouter.in_database('subordinate')
def olderInfoGetEdit(request):
    """
        老人编辑页信息
    :param request:
    :return:
    """

    def item(it: models.BasicInfoOfOlder, key, tp=str, foreign=False, foreignKey=None, isLocate=False):
        dt = tools.BaseData()
        dt.choice = []
        if foreign:
            dt.name = getattr(local, "param_{}".format(foreignKey)).value
        else:
            dt.name = getattr(local, "param_{}".format(key)).value
        if foreign:
            dt.codename = foreignKey
            if getattr(default, foreignKey, None):
                for i, iv in getattr(default, foreignKey).items():
                    n = tools.BaseData()
                    n.name, n.id = iv, i
                    dt.choice.append(n.toJson)
        else:
            dt.codename = key
            if getattr(default, key, None):
                for i, iv in getattr(default, key).items():
                    n = tools.BaseData()
                    n.name, n.id = iv, i
                    dt.choice.append(n.toJson)
        dt.autoflag = 0
        dt.source = None
        dt.value = None

        if foreign:
            if getattr(it, key, None):
                if not isLocate:
                    ctl = json.loads(getattr(getattr(it, key), 'ctrl'))
                    ###########################
                    dt.autoflag = ctl[foreignKey]['autoflag']
                    src = ctl[foreignKey]['source']
                    if src and type(src) == int:
                        dt.source = getattr(default, foreignKey)[src]
                    else:
                        dt.source = src
                else:
                    ctl = json.loads(getattr(it, 'ctrl'))
                    dt.autoflag = ctl[foreignKey]['autoflag']
                    src = ctl[foreignKey]['source']
                if tp == str:
                    dt.value = getattr(getattr(it, key), foreignKey)
                elif tp == int:
                    if isLocate:
                        dt.value = getattr(getattr(it, key), 'ora_index')
                        try:
                            dt.source = models.District.objects.get(ora_index=src).ora_name if src else None
                        except Exception as e:
                            if default.debug:
                                print(f"in the olderInfoGetEdit found district id not found {src}")
                    else:
                        dt.value = getattr(getattr(it, key), foreignKey, None) if getattr(it, key, None) else None
            else:
                dt.value = None
        else:
            ctl = json.loads(getattr(it, 'ctrl'))
            dt.autoflag = ctl[key]['autoflag']
            src = ctl[key]['source']
            if src and type(src) == int:
                dt.source = getattr(default, key)[src]
            else:
                dt.source = src
            if tp == str:
                dt.value = getattr(it, key)
            elif tp == int:
                dt.value = getattr(it, key, None)
            elif tp == time:
                dt.value = getattr(it, key).strftime('%Y-%m-%d') if getattr(it, key, None) else None
        return dt.toJson

    form = requestForms.OlderDetail(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    identityCard = form.cleaned_data['identityCard']
    ds = []
    for it in models.BasicInfoOfOlder.objects.select_related('flag', 'pensions', 'locate_street', 'locate_community',
                                                             'locate_county').filter(identityCard=identityCard):
        dt = tools.BaseData()
        dt.name = "必填信息"
        dt.codename = 'a'
        dt.sub = []
        dt.sub.append(item(it, 'name'))
        dt.sub.append(item(it, 'gender', tp=int))
        dt.sub.append(item(it, 'identityCard'))
        dt.sub.append(item(it, 'birthDay', tp=time))
        dt.sub.append(item(it, 'flag', tp=int, foreign=True, foreignKey='isDeath'))
        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "个人信息"
        dt.codename = 'b'
        dt.sub = []
        dt.sub.append(item(it, 'nationality', tp=int))
        dt.sub.append(item(it, 'education', tp=int))
        dt.sub.append(item(it, 'identityType', tp=int))
        dt.sub.append(item(it, 'marriageStatus', tp=int))
        dt.sub.append(item(it, 'politics', tp=int))
        dt.sub.append(item(it, 'telephone'))
        dt.sub.append(item(it, 'mobilephone'))

        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "位置信息"
        dt.codename = "c"
        dt.sub = []
        x = tools.BaseData()
        x.name = "所在地区"
        x.codename = "locate"
        tmp_data = [(tmp["value"], tmp["source"], tmp["autoflag"]) for tmp in
                    [item(it, 'locate_county', tp=int, foreign=True, foreignKey='locate_county', isLocate=True),
                     item(it, 'locate_street', tp=int, foreign=True, foreignKey='locate_street', isLocate=True),
                     item(it, 'locate_community', tp=int, foreign=True, foreignKey='locate_community', isLocate=True)]]
        x.value = [*map(lambda x: x[0] if x[0] else default.defaulNoneInt, tmp_data), ]
        x.source = ' '.join([*map(lambda x: x[1] if x[1] else '', tmp_data), ])
        x.autoflag = any([*map(lambda x: x[2] if x[2] else 0, tmp_data), ])
        dt.sub.append(x.toJson)
        dt.sub.append(item(it, 'address'))
        dt.sub.append(item(it, 'censusRegister'))
        dt.sub.append(item(it, 'registerNature', tp=int))
        dt.sub.append(item(it, 'postcode'))
        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "紧急联系人信息"
        dt.codename = "d"
        dt.sub = []
        dt.sub.append(item(it, 'emergencyPeople'))
        dt.sub.append(item(it, 'emergencyPhone'))
        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "养老信息"
        dt.codename = "e"
        dt.sub = []
        dt.sub.append(item(it, 'pensions', foreignKey='bjtCard', foreign=True))
        dt.sub.append(item(it, 'pensions', foreign=True, foreignKey='bankCard'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='incomingLevel'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='economicSource'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='careType'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='livingDegree'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='residenceStatus'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='healthStatus'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='vocation'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='employmentStatus'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='bodyStatus'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='laborCapacity'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='mininumLivingLevel'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='insured'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='medicalInsuranceType'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='insuranceType'))
        dt.sub.append(item(it, 'pensions', tp=int, foreign=True, foreignKey='homeOwnership'))
        dt.sub.append(item(it, 'flag', tp=int, foreign=True, foreignKey='isRetire'))

        dt.sub.append(item(it, 'flag', tp=int, foreign=True, foreignKey='isAbroadRelative'))
        dt.sub.append(item(it, 'flag', tp=int, foreign=True, foreignKey='isReservoirImmigrant'))
        dt.sub.append(item(it, 'flag', tp=int, foreign=True, foreignKey='isExservicee'))
        dt.sub.append(item(it, 'flag', tp=int, foreign=True, foreignKey='isReleased'))
        dt.sub.append(item(it, 'flag', tp=int, foreign=True, foreignKey='isNZJ'))
        dt.sub.append(item(it, 'flag', tp=int, foreign=True, foreignKey='isDisabled'))
        dt.sub.append(item(it, 'flag', tp=int, foreign=True, foreignKey='isLonely'))
        dt.sub.append(item(it, 'flag', tp=int, foreign=True, foreignKey='isSpecialSalvation'))
        dt.sub.append(item(it, 'flag', tp=int, foreign=True, foreignKey='isObjectTraditional'))
        dt.sub.append(item(it, 'flag', tp=int, foreign=True, foreignKey='isObjectServiced'))

        ds.append(dt.toJson)
        return tools.genErrorStatusResponse(error.status_200, ds)
    return tools.genErrorStatusResponse(error.status_notFound)


@dbRouter.in_database('subordinate')
def olderDistrictLevel(request):
    """
        老人选择地区信息
    :param request:
    :return:
    """

    def hierarchy(location):
        ds = []
        mx = max(default.belongs.keys())
        for son in models.District.objects.filter(Q(ora_parent=location) & Q(ora_status=1)).order_by(
                '-ora_weight').iterator():
            dt = tools.BaseData()
            dt.id, dt.name = son.ora_index, son.ora_name
            dt.sub = []
            if son.ora_level == mx:
                delattr(dt, 'sub')
                ds.append(dt.toJson)
                continue
            for i in hierarchy(son.ora_index):
                dt.sub.append(i)
            if not dt.sub:
                delattr(dt, 'sub')
            ds.append(dt.toJson)
        dt = tools.BaseData()
        dt.name, dt.id = default.defaultNoneString, "{}_{}".format(location, default.defaulNoneInt)
        ds.append(dt.toJson)
        return ds

    dt = tools.BaseData()
    dt.id, dt.name = default.defaultDetailLocations[0], default.defaultDetailLocations[1]
    data = hierarchy(dt.id)
    if data:
        dt.sub = data
    return tools.genErrorStatusResponse(error.status_200, data=[dt.toJson, ])


def olderBasicForm(request):
    """
        老人基础表单
    :param request:
    :return:
    """

    def item(key, tp=str):
        dt = tools.BaseData()
        dt.choice = []
        dt.value = None
        if tp == int:
            for k, v in getattr(default, key).items():
                x = tools.BaseData()
                x.id, x.name = k, v
                dt.choice.append(x.toJson)
            # 这是放默认值进去
            # dt.value = [*getattr(default, key).keys(), ][-1]

        dt.name = getattr(local, "param_{}".format(key)).value
        dt.codename = key
        if not dt.choice:
            delattr(dt, 'choice')
        return dt.toJson

    ds = []
    dt = tools.BaseData()
    dt.name = "必填信息"
    dt.codename = 'a'
    dt.sub = []
    dt.sub.append(item('name'))
    dt.sub.append(item('gender', tp=int))
    dt.sub.append(item('identityCard'))
    dt.sub.append(item('birthDay'))
    dt.sub.append(item('isDeath', tp=int))
    ds.append(dt.toJson)

    dt = tools.BaseData()
    dt.name = "个人信息"
    dt.codename = 'b'
    dt.sub = []
    dt.sub.append(item('nationality', tp=int))
    dt.sub.append(item('education', tp=int))
    dt.sub.append(item('identityType', tp=int))
    dt.sub.append(item('marriageStatus', tp=int))
    dt.sub.append(item('politics', tp=int))
    dt.sub.append(item('telephone'))
    dt.sub.append(item('mobilephone'))
    ds.append(dt.toJson)

    dt = tools.BaseData()
    dt.name = "位置信息"
    dt.codename = "c"
    dt.sub = []
    x = tools.BaseData()
    x.name = "所在地区"
    x.codename = "locate"
    dt.sub.append(x.toJson)
    dt.sub.append(item('address'))
    dt.sub.append(item('censusRegister'))
    dt.sub.append(item('registerNature', tp=int))
    dt.sub.append(item('postcode'))
    ds.append(dt.toJson)

    dt = tools.BaseData()
    dt.name = "紧急联系人信息"
    dt.codename = "d"
    dt.sub = []
    dt.sub.append(item(key='emergencyPeople'))
    dt.sub.append(item(key='emergencyPhone'))
    ds.append(dt.toJson)

    dt = tools.BaseData()
    dt.name = "养老信息"
    dt.codename = "e"
    dt.sub = []
    dt.sub.append(item(key='bjtCard'))
    dt.sub.append(item(key='bankCard'))
    dt.sub.append(item(tp=int, key='incomingLevel'))
    dt.sub.append(item(tp=int, key='economicSource'))
    dt.sub.append(item(tp=int, key='careType'))
    dt.sub.append(item(tp=int, key='livingDegree'))
    dt.sub.append(item(tp=int, key='residenceStatus'))
    dt.sub.append(item(tp=int, key='healthStatus'))
    dt.sub.append(item(tp=int, key='vocation'))
    dt.sub.append(item(tp=int, key='employmentStatus'))
    dt.sub.append(item(tp=int, key='bodyStatus'))
    dt.sub.append(item(tp=int, key='laborCapacity'))
    dt.sub.append(item(tp=int, key='mininumLivingLevel'))
    dt.sub.append(item(tp=int, key='insured'))
    dt.sub.append(item(tp=int, key='medicalInsuranceType'))
    dt.sub.append(item(tp=int, key='insuranceType'))
    dt.sub.append(item(tp=int, key='homeOwnership'))
    dt.sub.append(item(tp=int, key='isRetire'))

    dt.sub.append(item(tp=int, key='isAbroadRelative'))
    dt.sub.append(item(tp=int, key='isReservoirImmigrant'))
    dt.sub.append(item(tp=int, key='isExservicee'))
    dt.sub.append(item(tp=int, key='isReleased'))
    dt.sub.append(item(tp=int, key='isNZJ'))
    dt.sub.append(item(tp=int, key='isDisabled'))
    dt.sub.append(item(tp=int, key='isLonely'))
    dt.sub.append(item(tp=int, key='isSpecialSalvation'))
    dt.sub.append(item(tp=int, key='isObjectTraditional'))
    dt.sub.append(item(tp=int, key='isObjectServiced'))

    ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds)


def exportElderDataConditions(request):
    """
        导出老人条件获取
    :param request:
    :return:
    """
    item = tools.BaseData()
    item.exportFormat = [
        {"codename": 'csv文件格式', "value": "csv"},
        # {"codename": 'excel文件格式', "value": "xlsx"},
    ]
    genre = request.user.groups.all()[0].genre
    if genre in {local.countyAdmin.name, local.super.name, local.systemAdmin.name}:
        item.conditions = [
            {"codename": '当前查询数据', "value": "1"},
            {"codename": '所有数据', "value": "2"},
        ]
    else:
        item.conditions = [
            {"codename": '当前查询数据', "value": "1"},
        ]
    item.doc = default.exportDataHelpDoc
    return tools.genErrorStatusResponse(error.status_200, item.toJson)


def checkTaskStatus(request):
    """
        获取任务状态
    :param request:
    :return:
    """
    form = requestForms.TaskStatus(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    taskid = form.cleaned_data['taskid']
    response = tools.BaseData()
    value = cache.get(taskid)
    if value:
        response.state = value['state']
    else:
        response.state = "FAILURE"
    return tools.genErrorStatusResponse(error.status_200, response.toJson)


def downLoadExportData(request):
    """
        下载导出的数据
    :param request:
    :return:
    """
    form = requestForms.TaskStatus(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    taskid = form.cleaned_data['taskid']
    value = cache.get(taskid)
    if value and value['state'] == "SUCCESS":
        result = AsyncResult(id=value['taskid'])
        filename = os.path.basename(result.result)
        response = downloadServer(request, path="{}".format(filename),
                                  document_root=settings.MEDIA_ROOT)
        response['Content-Disposition'] = "attachment; filename={!s}".format(
            escape_uri_path(filename))
        return response
    else:
        return tools.genErrorStatusResponse(error.status_tasknotDone)


def exportElderData(request):
    """
        老人数据导出
    :param request: 
    :return: 
    """
    form = requestForms.ExportElderData(request.POST)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    format = form.cleaned_data['format']
    scope = form.cleaned_data['scope']
    # {"identityCard":xxxx,'gender':xxx,....}
    query = json.loads(form.cleaned_data['query'])
    query_form = requestForms.OlderInfo(query)
    if not query_form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    genre = request.user.groups.all()[0].genre
    query = query_form.cleaned_data
    query['user_genre'] = genre
    query['locate_ora_index'] = request.user.locate.ora_index if genre not in {local.super.name,
                                                                               local.systemAdmin.name} else None
    # resultid = tools.ID.genUniqueid()
    # 生成所有数据
    if int(scope) == 2:
        resultid = "export_all_data"
        if resultid in cache:
            return tools.genErrorStatusResponse(error.status_200, {'taskid': resultid})
    else:
        content = "{}_{}_{}".format(format, scope, json.dumps(query))
        resultid = tools.getMD5(content)
        if resultid in cache:
            return tools.genErrorStatusResponse(error.status_200, {'taskid': resultid})
    cache.set(resultid, {"state": "PENDING", "taskid": None}, timeout=3600)
    tasks.controllerExportDataAction_private.apply_async(
        kwargs={'format': format, 'scope': scope, 'query': query, 'cacheid': resultid})
    return tools.genErrorStatusResponse(error.status_200, {'taskid': resultid})


def exportInstitutionData(request):
    """
        机构数据导出
    :param request:
    :return:
    """
    form = requestForms.ExportElderData(request.POST)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    format = form.cleaned_data['format']
    scope = form.cleaned_data['scope']
    # {"identityCard":xxxx,'gender':xxx,....}
    query = json.loads(form.cleaned_data['query'])
    query_form = requestForms.InstitutionInfo(query)
    if not query_form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    query = query_form.cleaned_data
    result = tasks.exportInstitutionDataAsync_private.apply_async(
        kwargs={'format': format, 'scope': scope, 'query': query})
    return tools.genErrorStatusResponse(error.status_200, {'taskid': result.id})


def checkTaskStatusForInstitution(request):
    """
        获取任务状态
    :param request:
    :return:
    """
    form = requestForms.TaskStatus(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    taskid = form.cleaned_data['taskid']
    response = tools.BaseData()
    result = AsyncResult(id=taskid)
    response.state = result.state
    return tools.genErrorStatusResponse(error.status_200, response.toJson)


def downLoadExportInstitutionData(request):
    """
        下载机构导出的数据
    :param request:
    :return:
    """
    form = requestForms.TaskStatus(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    taskid = form.cleaned_data['taskid']
    result = AsyncResult(id=taskid)
    if result.state == 'SUCCESS':
        filename = os.path.basename(result.result)
        response = downloadServer(request, path="{}".format(filename),
                                  document_root=settings.MEDIA_ROOT)
        response['Content-Disposition'] = "attachment; filename={!s}".format(
            escape_uri_path(filename))
        return response
    else:
        return tools.genErrorStatusResponse(error.status_tasknotDone)


def olderInfoUpdateOrCreate(request, created=False):
    """
        老人信息修改
    :param request:
    :return:
    """
    form = requestForms.OlderInfoModified(QueryDict(request.body))
    if not form.is_valid():
        if default.debug:
            print(f"in the olderInfoUpdateOrCreate form error {form.errors}  {QueryDict(request.body)}")
        return tools.genErrorStatusResponse(error.status_formError)
    changed = form.cleaned_data['changed']
    # changed 格式
    # [{'codename':xxxx,'autoflag':0,'value':xxxxx},{'codename':xxxx,'autoflag':0,'value':xxxxx}]
    try:
        jdata = json.loads(changed)
    except Exception as e:
        if default.debug:
            print(f"in the olderInfoUpdateOrCreate json form data error {e}")
        return tools.genErrorStatusResponse(error.status_checkValueError)
    keys = {
        "identityCard",
        "gender",
        "name",
        "birthDay",
        "nationality",
        "education",
        "politics",
        "marriageStatus",
        "identityType",
        "locate_community",
        "locate_street",
        "locate_county",
        "address",
        "postcode",
        "censusRegister",
        "registerNature",
        "emergencyPeople",
        "emergencyPhone",
        "telephone",
        "mobilephone"
    }
    flag_keys = {
        "isObjectServiced",
        "isObjectTraditional",
        "isSpecialSalvation",
        "isLonely",
        "isDisabled",
        "isNZJ",
        "isReleased",
        "isExservicee",
        "isReservoirImmigrant",
        "isAbroadRelative",
        "isDeath",
        "isRetire"
    }
    pensions_keys = {
        "bjtCard",
        "bankCard",
        "insuranceType",
        "medicalInsuranceType",
        "insured",
        "mininumLivingLevel",
        "laborCapacity",
        "bodyStatus",
        "employmentStatus",
        "vocation",
        "healthStatus",
        "residenceStatus",
        "livingDegree",
        "careType",
        "economicSource",
        "incomingLevel",
        "homeOwnership"
    }
    for it in jdata:
        if it['codename'] == 'identityCard':
            if it['value']:
                # create process
                identityCard = it['value']
                break
            else:
                return tools.genErrorStatusResponse(error.status_checkValueError)
    now = make_aware(datetime.datetime.now())
    log = tools.BaseData()
    log.username = request.user.username
    if created:
        objs = models.BasicInfoOfOlder.objects.filter(identityCard=identityCard)
        if objs.exists():
            return tools.genErrorStatusResponse(error.status_foundDuplicateID)
        try:
            # 默认值初始化
            kwargs = {}
            for i in keys:
                value = getattr(default, i, None)
                if value:
                    default_value = [*value.keys(), ][-1]
                    kwargs[i] = default_value
                else:
                    kwargs[i] = None
            pensions_kwargs = {}
            for i in pensions_keys:
                value = getattr(default, i, None)
                if value:
                    default_value = [*value.keys(), ][-1]
                    pensions_kwargs[i] = default_value
                else:
                    pensions_kwargs[i] = None

            flag_kwargs = {}
            for i in flag_keys:
                value = getattr(default, i, None)
                if value:
                    default_value = [*value.keys(), ][-1]
                    flag_kwargs[i] = default_value
                else:
                    flag_kwargs[i] = None

            ctl = {}
            for i in keys:
                ctl[i] = {'autoflag': 0, 'source': kwargs[i]}
            flag_ctl = {}
            for i in flag_keys:
                flag_ctl[i] = {'autoflag': 0, 'source': flag_kwargs[i]}
            pensions_ctl = {}
            for i in pensions_keys:
                pensions_ctl[i] = {'autoflag': 0, 'source': pensions_kwargs[i]}

            with transaction.atomic():
                for it in jdata:
                    codename, value = it['codename'], it['value']
                    if not value:
                        if codename == 'locate_county':
                            kwargs[codename] = models.District.objects.get(ora_index=default.defaultDetailLocations[0])
                            ctl[codename]["source"] = default.defaultDetailLocations[0]
                        continue
                    if codename in keys:
                        if codename in {'birthDay'}:
                            kwargs[codename] = make_aware(datetime.datetime.strptime(value, '%Y-%m-%d'))
                        elif codename in {'locate_county', 'locate_street', 'locate_community'}:
                            if value == default.defaulNoneInt:
                                kwargs[codename] = None
                                ctl[codename]["source"] = None
                            else:
                                kwargs[codename] = models.District.objects.get(ora_index=value)
                                ctl[codename]["source"] = value
                        else:
                            kwargs[codename] = value
                            ctl[codename]["source"] = value
                        ctl[codename]["autoflag"] = 1
                    elif codename in pensions_keys:
                        pensions_kwargs[codename] = value
                        pensions_ctl[codename]['autoflag'] = 1
                        pensions_ctl[codename]['source'] = value
                    elif codename in flag_keys:
                        flag_kwargs[codename] = value
                        flag_ctl[codename]['autoflag'] = 1
                        flag_ctl[codename]['source'] = value

                flag_kwargs['ctrl'] = json.dumps(flag_ctl)
                kwargs['ctrl'] = json.dumps(ctl)
                pensions_kwargs['ctrl'] = json.dumps(pensions_ctl)
                flag = models.ElderFlag.objects.create(**flag_kwargs)
                pensions = models.PensionsInfo.objects.create(**pensions_kwargs)
                kwargs['flag'] = flag
                kwargs['pensions'] = pensions
                kwargs['creator'] = request.user
                kwargs['createTime'] = now
                kwargs['lastTime'] = now
                obj = models.BasicInfoOfOlder.objects.create(**kwargs)
                log.action, log.content = local.log_elderCreate.value, jdata
                tasks.logRecord.delay(log.toJson)
                tasks.updateElderRelatedCache.delay()
                tasks.elderPositionGET.delay(identityCard)
                return tools.genErrorStatusResponse(error.status_200)
        except Exception as e:
            if default.debug:
                print(f"in the olderInfoUpdateOrCreate create found error {e}")
            return tools.genErrorStatusResponse(error.status_foundError)
    else:
        try:
            with transaction.atomic():
                for obj in models.BasicInfoOfOlder.objects.filter(identityCard=identityCard):
                    ctl = json.loads(getattr(obj, 'ctrl'))
                    flag_ctl = json.loads(getattr(obj.flag, 'ctrl'))
                    pensions_ctl = json.loads(getattr(obj.pensions, 'ctrl'))
                    for it in jdata:
                        if it['codename'] == 'identityCard':
                            continue
                        codename, autoflag, value = it['codename'], it['autoflag'], it['value']
                        if not value:
                            options = getattr(default, codename, None)
                            if options:
                                value = list(options.keys())[-1]
                        if autoflag:
                            if codename in keys:
                                if codename in {'birthDay'}:
                                    setattr(obj, codename, make_aware(datetime.datetime.strptime(value, '%Y-%m-%d')))
                                elif codename in {'locate_county', 'locate_street', 'locate_community'}:
                                    if value == default.defaulNoneInt:
                                        if codename == 'locate_county':
                                            setattr(obj, codename, models.District.objects.get(
                                                ora_index=default.defaultDetailLocations[0]))
                                        else:
                                            setattr(obj, codename, None)
                                    else:
                                        setattr(obj, codename, models.District.objects.get(ora_index=value))
                                else:
                                    setattr(obj, codename, value)
                                vx = ctl[codename]
                                vx['autoflag'] = 1
                            elif codename in pensions_keys:
                                setattr(obj.pensions, codename, value)
                                vx = pensions_ctl[codename]
                                vx['autoflag'] = 1
                            elif codename in flag_keys:
                                setattr(obj.flag, codename, value)
                                vx = flag_ctl[codename]
                                vx['autoflag'] = 1
                        else:
                            if codename in keys:
                                vx = ctl[codename]
                                vx['autoflag'] = 0
                                source = vx['source']
                                if codename in {'birthDay'}:
                                    if source:
                                        setattr(obj, codename,
                                                make_aware(datetime.datetime.strptime(source, '%Y-%m-%d')))
                                    else:
                                        setattr(obj, codename, None)
                                elif codename in {'locate_county', 'locate_street', 'locate_community'}:
                                    if source:
                                        setattr(obj, codename, models.District.objects.get(ora_index=source))
                                    else:
                                        setattr(obj, codename, None)
                                else:
                                    setattr(obj, codename, source)
                            elif codename in pensions_keys:
                                vx = pensions_ctl[codename]
                                vx['autoflag'] = 0
                                setattr(obj.pensions, codename, vx["source"])
                            elif codename in flag_keys:
                                vx = flag_ctl[codename]
                                vx['autoflag'] = 0
                                setattr(obj.flag, codename, vx["source"])
                    obj.ctrl = json.dumps(ctl)
                    obj.flag.ctrl = json.dumps(flag_ctl)
                    obj.flag.save()
                    obj.pensions.ctrl = json.dumps(pensions_ctl)
                    obj.pensions.save()
                    obj.save()
                    log.action, log.content = local.log_elderEdit.value, jdata
                    tasks.logRecord.delay(log.toJson)
                    tasks.updateElderRelatedCache.delay()
                    return tools.genErrorStatusResponse(error.status_200)
                else:
                    return tools.genErrorStatusResponse(error.status_notFound)
        except Exception as e:
            if default.debug:
                print(f"in the olderInfoUpdateOrCreate update error {e}")
        return tools.genErrorStatusResponse(error.status_foundError)


@dbRouter.in_database("subordinate")
def olderHealthArchive_conditions(request):
    """
        老人健康,条件获取,目前是假数据呈现
    :param request:
    :return:
    """
    keys = [
        'belongLocate',
        "name",
        # 'insuranceType',
        'identityCard',
        "birthDay",

    ]

    street_institutions = []
    for street in getAllStreets2(request):
        id_, name, level = street['id'], street['name'], street['level']
        institutions: list = []
        index = 0
        if id_ == None:
            query = Q(locate_county__ora_index=default.defaultDetailLocations[0])
            institution = tools.BaseData()
            institution.name, institution.institutionid = "全部", None
            institutions.append(institution.toJson)
            record = tools.BaseData()
            record.id, record.name, record.level, record.institutions = id_, name, level, institutions
            street_institutions.append(record.toJson)
            continue
        else:
            query = Q(locate_county__ora_index=default.defaultDetailLocations[0])
            query &= Q(locate_street__ora_index=id_)
        for item in models.InstitutionInfo.objects.filter(query).iterator():
            if index == 0:
                institution = tools.BaseData()
                institution.name, institution.institutionid = "全部", item.institutionid
                institutions.append(institution.toJson)
            institution = tools.BaseData()
            institution.name, institution.institutionid = item.name, item.institutionid
            institutions.append(institution.toJson)
            index += 1
        record = tools.BaseData()
        record.id, record.name, record.level, record.institutions = id_, name, level, institutions
        street_institutions.append(record.toJson)

    ret: list = []
    for index, key in enumerate(keys):
        item = tools.BaseData()
        atr = "param_{}".format(key)
        item.name = getattr(local, atr).value
        item.codename = key
        # 前端要求添加
        if index <= 3:
            item.status = 1
        else:
            item.status = 0
        item.conditions = []
        if key == "belongLocate":
            item.conditions = street_institutions
        elif key == "insuranceType":
            if getattr(default, key, None):
                o = tools.BaseData()
                o.key = "全部"
                o.value = None
                item.conditions.append(o.toJson)
                for k, v in getattr(default, key).items():
                    x = tools.BaseData()
                    x.key = v
                    x.value = k
                    item.conditions.append(x.toJson)
        else:
            delattr(item, 'conditions')
        ret.append(item.toJson)
    return tools.genErrorStatusResponse(error.status_200, ret)


@dbRouter.in_database("subordinate")
def olderDataVisual_conditions(request):
    """
        老人健康,条件获取,目前是假数据呈现
    :param request:
    :return:
    """
    keys = [
        'belongLocate'
    ]

    street_institutions = []
    for street in getAllStreets2(request):
        id_, name, level = street['id'], street['name'], street['level']
        institutions: list = []
        index = 0
        if id_ == None:
            institution = tools.BaseData()
            institution.name, institution.institutionid = "全部", None
            institutions.append(institution.toJson)
            record = tools.BaseData()
            record.id, record.name, record.level, record.institutions = id_, name, level, institutions
            street_institutions.append(record.toJson)
            continue
        else:
            query = Q(locate_county__ora_index=default.defaultDetailLocations[0])
            query &= Q(locate_street__ora_index=id_)
        for item in models.InstitutionInfo.objects.filter(query).iterator():
            if index == 0:
                institution = tools.BaseData()
                institution.name, institution.institutionid = "全部", item.institutionid
                institutions.append(institution.toJson)
            institution = tools.BaseData()
            institution.name, institution.institutionid = item.name, item.institutionid
            institutions.append(institution.toJson)
            index += 1
        record = tools.BaseData()
        record.id, record.name, record.level, record.institutions = id_, name, level, institutions
        street_institutions.append(record.toJson)

    ret: list = []
    for index, key in enumerate(keys):
        item = tools.BaseData()
        atr = "param_{}".format(key)
        item.name = getattr(local, atr).value
        item.codename = key
        # 前端要求添加
        if index <= 3:
            item.status = 1
        else:
            item.status = 0
        item.conditions = []
        if key == "belongLocate":
            item.conditions = street_institutions
        else:
            delattr(item, 'conditions')
        ret.append(item.toJson)
    return tools.genErrorStatusResponse(error.status_200, ret)


def careCenterCondition(request):
    """
        养老照料中心条件
    :param request:
    :return:
    """
    keys = [
        'locateAll',
    ]
    ret = []
    for index, it in enumerate(keys):
        item = tools.BaseData()
        atr = "institution_{}".format(it)
        item.name = getattr(local, atr).value
        item.codename = it
        # 前端要求添加
        if index <= 3:
            item.status = 1
        else:
            item.status = 0
        item.conditions = []
        if it == 'locateAll':
            item.conditions = getAllStreets2(request)
        if not item.conditions:
            delattr(item, 'conditions')
        ret.append(item.toJson)
    return tools.genErrorStatusResponse(error.status_200, ret)


def careCenterList(request, institutionType=1):
    """
        根据条件,获取列表
    :param request:
    :return:
    """
    form = requestForms.CareCenter(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    street_ids = set()
    county_ids = set()
    # 默认丰台区的id
    county_ids.add(default.defaultDetailLocations[0])
    form = namedtuple('tmp', ['locate_street', 'page', 'size'])(**form.cleaned_data)
    try:
        slice_ = tools.getPageSlice(form.size, form.page)
    except Exception:
        return tools.genErrorStatusResponse(error.status_checkValueError)
    if form.locate_street:
        if form.locate_street == default.defaultDetailLocations[0]:
            # 区角色,点击全部的 场景
            pass
        else:
            street_ids.add(form.locate_street)
    query = Q()
    if county_ids:
        query &= Q(locate_county__ora_index__in=county_ids)
    if street_ids:
        if default.defaulNoneInt in street_ids:
            query &= Q(locate_street=None)
        else:
            query &= Q(locate_street__ora_index__in=street_ids)
    query &= Q(operatingStatus__in={1, 3})
    # instituionalType=1是照料中心
    query &= Q(instituionalType=institutionType)
    ret: list = []
    total = models.InstitutionInfo.objects.filter(query).count()
    for it in models.InstitutionInfo.objects.filter(query).order_by('locate_street__ora_name')[slice_]:
        dt = tools.BaseData()
        dt.name = it.name
        dt.institutionid = it.institutionid
        ret.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ret, **{"total": total})


def institutionCondition(request):
    """
        机构查询条件
    :param request:
    :return:
    """
    keys = [
        'locateAll',
        'instituionalType',
        'institutionalNature',
        'name',
        'operatingUnit',
        'operatingStatus',
        'address',
        'postcode',
        'liaison',
        'phone',
        'areaCovered',
        'areaUsed',
        'numOfBed',
        'foundTime',
        'institutionCode',
        'licenseOfMedical',
        'licenseOfQualification'
    ]

    ds = []
    for index, it in enumerate(keys):
        dt = tools.BaseData()
        atr = "institution_{}".format(it)
        dt.name = getattr(local, atr).value
        dt.codename = it
        dt.status = 0
        # 前端要求添加
        if index <= 3:
            dt.status = 1
        dt.conditions = []
        if it == 'locateAll':
            dt.conditions = getAllStreets2(request)
        elif it == 'instituionalType':
            o = tools.BaseData()
            o.key = "全部"
            o.value = None
            dt.conditions.append(o.toJson)

            o = tools.BaseData()
            # 扭曲的修改,照料中心是1,养老机构（照料中心以外）是2
            o.key = "养老机构"
            o.value = 12
            dt.conditions.append(o.toJson)
            for k, v in getattr(default, it).items():
                x = tools.BaseData()
                x.key = v
                x.value = k
                dt.conditions.append(x.toJson)
        elif it == 'operatingStatus':
            o = tools.BaseData()
            # 扭曲的修改,运营是1,建设是3
            o.key = "运营与建设中"
            o.value = 13
            dt.conditions.append(o.toJson)
            for k, v in getattr(default, it).items():
                x = tools.BaseData()
                x.key = v
                x.value = k
                dt.conditions.append(x.toJson)
            o = tools.BaseData()
            o.key = "全部"
            o.value = None
            dt.conditions.append(o.toJson)
            dt.status = 1
        else:
            if getattr(default, it, None):
                o = tools.BaseData()
                o.key = "全部"
                o.value = None
                dt.conditions.append(o.toJson)
                for k, v in getattr(default, it).items():
                    x = tools.BaseData()
                    x.key = v
                    x.value = k
                    dt.conditions.append(x.toJson)
        if not dt.conditions:
            delattr(dt, 'conditions')
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds)


def institutionMakeQuery(request, baseForm):
    """
        机构表单处理
    :param request:
    :param baseForm:
    :return:
    """

    def checkid(atr, val):
        for k, v in getattr(default, atr).items():
            if k == val:
                return True
        return False

    keys = [
        "locate_street",
        "name",
        "instituionalType",
        "address",
        "postcode",
        "operatingUnit",
        "liaison",
        'phone',
        "numOfBed",
        "institutionalNature",
        "institutionCode",
        "licenseOfMedical",
        "licenseOfQualification",
        'operatingStatus',
        "areaUsed",
        "areaCovered",
        'institutionid',
        "createTime",
        'page',
        'size'
    ]
    try:
        form = namedtuple('tmp', keys)(**baseForm.cleaned_data)
    except Exception as e:
        if default.debug:
            print(f"in the institutionMakeQuery found  form error {baseForm.cleaned_data}")
        return None, None
    street_ids = set()
    county_ids = set()

    for key in keys:
        # 扭曲的需求,不做判断,后面做做特殊处理2019-12-19
        if key in {'instituionalType', 'operatingStatus'}:
            continue
        val = getattr(form, key)
        if val:
            try:
                if val not in getattr(default, key):
                    return None, form
            except AttributeError:
                continue
    # 默认丰台区的id
    county_ids.add(default.defaultDetailLocations[0])
    if form.locate_street:
        if form.locate_street == default.defaultDetailLocations[0]:
            # 区角色,点击全部的 场景
            pass
        else:
            street_ids.add(form.locate_street)
    query = Q()
    if county_ids:
        query &= Q(locate_county__ora_index__in=county_ids)
    if street_ids:
        if default.defaulNoneInt in street_ids:
            query &= Q(locate_street=None)
        else:
            query &= Q(locate_street__ora_index__in=street_ids)
    if form.name:
        query &= Q(name__iregex=form.name)
    if form.instituionalType:
        # 扭曲的修改,照料中心是1,养老机构（照料中心以外）是2
        if form.instituionalType == 12:
            query &= Q(instituionalType__in={1, 2})
        else:
            if not checkid('instituionalType', form.instituionalType):
                return None, form
            query &= Q(instituionalType=form.instituionalType)
    if form.operatingStatus:
        # 扭曲的修改,运营中1,建设中3
        if form.operatingStatus == 13:
            query &= Q(operatingStatus__in={1, 3})
        else:
            if not checkid('operatingStatus', form.operatingStatus):
                return None, form
            query &= Q(operatingStatus=form.operatingStatus)
    if form.address:
        query &= Q(address__iregex=form.address)
    if form.postcode:
        query &= Q(postcode=form.postcode)
    if form.operatingUnit:
        query &= Q(operatingUnit__iregex=form.operatingUnit)
    if form.liaison:
        query &= Q(contact__icontains=form.liaison)
    if form.phone:
        query &= Q(contact__iregex=form.phone)
    if form.areaUsed:
        try:
            start, end = form.areaUsed.split(';')
            start, end = float(start), float(end)
            query &= Q(areaUsed__gte=start) & Q(areaUsed__lte=end)
        except Exception as e:
            if default.debug:
                print(f"in the institutionMakeQuery fun start,end areaUsed error {e}")
            return None, form
    if form.areaCovered:
        try:
            start, end = form.areaCovered.split(';')
            start, end = float(start), float(end)
            query &= Q(areaCovered__gte=start) & Q(areaCovered__lte=end)
        except Exception as e:
            if default.debug:
                print(f"in the institutionMakeQuery fun start,end areaCovered error {e}")
            return None, form
    if form.createTime:
        try:
            start, end = form.createTime.split(';')
            start, end = make_aware(datetime.datetime.strptime(start, '%Y-%m-%d')), make_aware(
                datetime.datetime.strptime(end, '%Y-%m-%d'))
            query &= Q(foundTime__gte=start) & Q(foundTime__lte=end)
        except Exception as e:
            if default.debug:
                print(f"in the institutionMakeQuery fun start,end time error {e}")
            return None, form
    if form.numOfBed:
        try:
            s, e = form.numOfBed.split(";")
            query &= Q(numOfBed__gte=int(s)) & Q(numOfBed__lte=int(e))
        except Exception as e:
            return None, form
    if form.institutionalNature:
        if not checkid('institutionalNature', form.institutionalNature):
            return None, form
        query &= Q(institutionalNature=form.institutionalNature)
    if form.institutionCode:
        query &= Q(institutionCode=form.institutionCode)
    if form.licenseOfMedical:
        query &= Q(licenseOfMedical=form.licenseOfMedical)
    if form.licenseOfQualification:
        query &= Q(licenseOfQualification=form.licenseOfQualification)
    if default.debug:
        print(f"in institutionMakeQuery will return query {query}")
    return query, form


@dbRouter.in_database("subordinate")
def institutionsList(request):
    """
        机构查询接口
    :param request:
    :return:
    """
    form = requestForms.InstitutionInfo(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    query, form = institutionMakeQuery(request, form)
    if not query:
        return tools.genErrorStatusResponse(error.status_checkValueError)
    try:
        slice_ = tools.getPageSlice(form.size, form.page)
    except Exception:
        return tools.genErrorStatusResponse(error.status_checkValueError)

    tmp: list = []
    total = models.InstitutionInfo.objects.filter(query).count()
    for it in \
            models.InstitutionInfo.objects.select_related('locate_street', 'locate_county').filter(query).order_by(
                'locate_street__ora_name')[
                slice_]:
        dt = tools.BaseData()
        dt.name = it.name
        dt.institutionid = it.institutionid
        dt.institutionalNature = getattr(default, 'institutionalNature')[
            it.institutionalNature] if it.institutionalNature else ''
        dt.instituionalType = getattr(default, 'instituionalType')[it.instituionalType] if it.instituionalType else ''
        dt.instituionalType_int = it.instituionalType
        dt.locate = "{}/{}".format(it.locate_county.ora_name if it.locate_county else '',
                                   it.locate_street.ora_name if it.locate_street else '')
        dt.address = it.address
        dt.liaison = ast.literal_eval(it.contact) if it.contact else None
        dt.foundTime = it.foundTime.strftime('%Y-%m-%d') if it.foundTime else None
        dt.areaUsed = it.areaUsed
        dt.areaCovered = it.areaCovered
        dt.longitude = it.longitude
        dt.latitude = it.latitude
        dt.numOfBed = it.numOfBed
        tmp.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, tmp, **{'total': total})


@dbRouter.in_database("subordinate")
def institutionDetail(request):
    """
        机构详情页
    :param request:
    :return:
    """

    def item(it: models.InstitutionInfo, key, tp=str, foreign=False, foreignKey=None, isLocate=False):
        dt = tools.BaseData()
        if foreign:
            dt.name = getattr(local, "institution_{}".format(foreignKey)).value
        else:
            dt.name = getattr(local, "institution_{}".format(key)).value
        if foreign:
            if getattr(it, key, None):
                if tp == str:
                    dt.value = getattr(getattr(it, key), foreignKey)
                elif tp == int:
                    if isLocate:
                        dt.value = getattr(getattr(it, key), 'ora_name')
                    else:
                        dt.value = getattr(default, foreignKey)[getattr(getattr(it, key), foreignKey)] if getattr(
                            getattr(it, key),
                            foreignKey,
                            None) else None
            else:
                dt.value = None
        else:
            if tp == str:
                if key in {'areaUsed', 'areaCovered'}:
                    if getattr(it, key, None):
                        dt.value = "{} ㎡".format(getattr(it, key))
                    else:
                        dt.value = getattr(it, key)
                else:
                    dt.value = getattr(it, key)
            elif tp == int:
                dt.value = getattr(default, key)[getattr(it, key)] if getattr(it, key, None) else None
            elif tp == time:
                dt.value = getattr(it, key).strftime('%Y-%m-%d') if getattr(it, key, None) else None
        return dt.toJson

    form = requestForms.InstitutionDetail(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    institutionid = form.cleaned_data['institutionid']
    ds = []
    for it in models.InstitutionInfo.objects.filter(institutionid=institutionid):
        dt = tools.BaseData()
        dt.name = "基本信息"
        dt.sub = []
        dt.sub.append(item(it, 'name'))
        dt.sub.append(item(it, 'instituionalType', tp=int))
        dt.sub.append(item(it, 'operatingUnit'))
        dt.sub.append(item(it, 'operatingStatus', tp=int))
        dt.sub.append(item(it, 'institutionalNature', tp=int))
        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "位置信息"
        dt.sub = []
        x = tools.BaseData()
        x.name = "所在地区"
        x.value = ';'.join([*map(lambda x: x if x else default.defaultNoneString, [
            item(it, 'locate_county', tp=int, foreign=True, foreignKey='locate_county', isLocate=True)['value'],
            item(it, 'locate_street', tp=int, foreign=True, foreignKey='locate_street', isLocate=True)['value'],
        ]), ])
        dt.sub.append(x.toJson)
        dt.sub.append(item(it, 'address'))
        dt.sub.append(item(it, 'postcode'))
        dt.sub.append(item(it, 'latitude'))
        dt.sub.append(item(it, 'longitude'))
        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "联系人信息"
        dt.sub = []
        if it.contact:
            for index, x in enumerate(ast.literal_eval(it.contact)):
                liaison = tools.BaseData()
                liaison.name = "联系人"
                liaison.value = x['liaison']
                dt.sub.append(liaison.toJson)
                liaison = tools.BaseData()
                liaison.name = "电话"
                liaison.value = x['phone']
                dt.sub.append(liaison.toJson)
        else:
            liaison = tools.BaseData()
            liaison.name = "联系人"
            liaison.value = "未定义"
            dt.sub.append(liaison.toJson)
            liaison = tools.BaseData()
            liaison.name = "电话"
            liaison.value = "未定义"
            dt.sub.append(liaison.toJson)
        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "设施信息"
        dt.sub = []
        dt.sub.append(item(it, 'areaCovered'))
        dt.sub.append(item(it, 'areaUsed'))
        dt.sub.append(item(it, 'numOfBed'))
        dt.sub.append(item(it, 'institutionCode'))
        dt.sub.append(item(it, 'licenseOfMedical'))
        dt.sub.append(item(it, 'licenseOfQualification'))
        dt.sub.append(item(it, 'foundTime', tp=time))
        ds.append(dt.toJson)
        return tools.genErrorStatusResponse(error.status_200, ds)
    else:
        return tools.genErrorStatusResponse(error.status_notFound)


def institutionEditDetail(request):
    """
        编辑页获取
    :param request:
    :return:
    """

    def item(it: models.InstitutionInfo, key, tp=str, foreign=False, foreignKey=None, isLocate=False):
        dt = tools.BaseData()
        if foreign:
            dt.name = getattr(local, "institution_{}".format(foreignKey)).value
        else:
            dt.name = getattr(local, "institution_{}".format(key)).value
        dt.codename = key
        dt.choice = []
        if getattr(default, key, None):
            for k, v in getattr(default, key).items():
                item = tools.BaseData()
                item.id = k
                item.name = v
                dt.choice.append(item.toJson)
        if foreign:
            if getattr(it, key, None):
                if tp == str:
                    dt.value = getattr(getattr(it, key), foreignKey)
                elif tp == int:
                    if isLocate:
                        dt.value = getattr(getattr(it, key), 'ora_index')
                    else:
                        dt.value = getattr(getattr(it, key), foreignKey)
            else:
                dt.value = None
        else:
            if tp == str:
                dt.value = getattr(it, key)
            elif tp == int:
                dt.value = getattr(it, key, None)
            elif tp == time:
                dt.value = getattr(it, key).strftime('%Y-%m-%d') if getattr(it, key, None) else None
        if not dt.choice:
            delattr(dt, 'choice')
        return dt.toJson

    form = requestForms.InstitutionDetail(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    institutionid = form.cleaned_data['institutionid']
    ds = []
    for it in models.InstitutionInfo.objects.filter(institutionid=institutionid):
        dt = tools.BaseData()
        dt.name = "基本信息"
        dt.codename = 'a'
        dt.sub = []
        dt.sub.append(item(it, 'name'))
        dt.sub.append(item(it, 'instituionalType', tp=int))
        dt.sub.append(item(it, 'operatingUnit'))
        dt.sub.append(item(it, 'operatingStatus', tp=int))
        dt.sub.append(item(it, 'institutionalNature', tp=int))
        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "位置信息"
        dt.codename = 'b'
        dt.sub = []
        x = tools.BaseData()
        x.name = "所在地区"
        x.codename = 'locate'
        x.value = [*map(lambda x: x if x else default.defaulNoneInt, [
            item(it, 'locate_county', tp=int, foreign=True, foreignKey='locate_county', isLocate=True)['value'],
            item(it, 'locate_street', tp=int, foreign=True, foreignKey='locate_street', isLocate=True)['value'],
        ]), ]
        x.choice = institutionDistrictLevel(request, onlyData=True)
        dt.sub.append(x.toJson)
        dt.sub.append(item(it, 'address'))
        dt.sub.append(item(it, 'latitude'))
        dt.sub.append(item(it, 'longitude'))
        dt.sub.append(item(it, 'postcode'))
        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "联系人信息"
        dt.codename = 'c'
        dt.sub = []
        if it.contact:
            for index, x in enumerate(ast.literal_eval(it.contact)):
                liaison = tools.BaseData()
                liaison.name = x['liaison']
                liaison.value = x['phone']
                liaison.codename = string.ascii_letters[index]
                dt.sub.append(liaison.toJson)
            size = 6 - len(dt.sub)
            for x in range(size):
                liaison = tools.BaseData()
                liaison.name = None
                liaison.value = None
                liaison.codename = string.ascii_letters[index + x + 1]
                dt.sub.append(liaison.toJson)
        else:
            for x in range(6):
                liaison = tools.BaseData()
                liaison.name = None
                liaison.value = None
                liaison.codename = string.ascii_letters[x]
                dt.sub.append(liaison.toJson)
        ds.append(dt.toJson)

        dt = tools.BaseData()
        dt.name = "设施信息"
        dt.codename = 'd'
        dt.sub = []
        dt.sub.append(item(it, 'areaCovered'))
        dt.sub.append(item(it, 'areaUsed'))
        dt.sub.append(item(it, 'numOfBed'))
        dt.sub.append(item(it, 'institutionCode'))
        dt.sub.append(item(it, 'licenseOfMedical'))
        dt.sub.append(item(it, 'licenseOfQualification'))
        dt.sub.append(item(it, 'foundTime', tp=time))
        ds.append(dt.toJson)
        return tools.genErrorStatusResponse(error.status_200, ds)
    else:
        return tools.genErrorStatusResponse(error.status_notFound)


def institutionUpdateOrCreate(request, created=False):
    """
        机构信息的编辑或建立
    :param request:
    :param created:
    :return:
    """
    form = requestForms.OlderInfoModified(QueryDict(request.body))
    if not form.is_valid():
        if default.debug:
            print(f"in the institutionUpdateOrCreate form error {form.errors}  {QueryDict(request.body)}")
        return tools.genErrorStatusResponse(error.status_formError)
    changed = form.cleaned_data['changed']
    # changed 格式
    # [{'codename':xxxx,'value':xxxxx},{'codename':xxxx,'value':xxxxx}]
    try:
        jdata = json.loads(changed)
    except Exception as e:
        if default.debug:
            print(f"in the institutionUpdateOrCreate json form data error {e}")
        return tools.genErrorStatusResponse(error.status_checkValueError)
    keys = {
        "institutionid",
        "name",
        "instituionalType",
        "address",
        "postcode",
        "operatingUnit",
        "liaison",
        "locate_street",
        "numOfBed",
        "institutionalNature",
        "institutionCode",
        "licenseOfMedical",
        "licenseOfQualification",
        "areaUsed",
        "areaCovered",
        "foundTime",
        "operatingStatus"
    }
    institutionid = None
    for it in jdata:
        if it['codename'] == 'institutionid':
            if it['value']:
                # create process
                institutionid = it['value']
            break
    now = make_aware(datetime.datetime.now())
    log = tools.BaseData()
    log.username = request.user.username
    if created:
        try:
            kwargs = {}
            for i in keys:
                if i in {'liaison'}:
                    continue
                value = getattr(default, i, None)
                if value:
                    default_value = [*value.keys(), ][-1]
                else:
                    default_value = None
                kwargs[i] = default_value
            kwargs['institutionid'] = str(tools.ID.genUniqueid())
            with transaction.atomic():
                for item in jdata:
                    codename, value = item['codename'], item['value']
                    if not value:
                        continue
                    if codename in {'foundTime'}:
                        kwargs[codename] = make_aware(datetime.datetime.strptime(value, '%Y-%m-%d'))
                    elif codename in {'liaison'}:
                        for x in value:
                            liaison, phone = x['liaison'], x['phone']
                        if len(value) < 6:
                            raise Exception("liaison phone number is not less than 6")
                        kwargs['contact'] = value
                    elif codename in {'instituionalType', 'institutionalNature', 'operatingStatus'}:
                        if value not in getattr(default, codename):
                            return tools.genErrorStatusResponse(error.status_checkValueError)
                        kwargs[codename] = value
                    elif codename in {'locate_street'}:
                        # 未定义地区-1
                        if value == default.defaulNoneInt:
                            pass
                        else:
                            kwargs['locate_street'] = models.District.objects.get(ora_index=value)
                        kwargs['locate_county'] = models.District.objects.get(
                            ora_index=default.defaultDetailLocations[0])
                    else:
                        kwargs[codename] = value if value else kwargs[codename]
                if 'locate_county' not in kwargs:
                    kwargs['locate_county'] = models.District.objects.get(
                        ora_index=default.defaultDetailLocations[0])
                kwargs['createTime'] = now
                kwargs['lastTime'] = now
                kwargs['lastModifier'] = request.user
                models.InstitutionInfo.objects.create(**kwargs)
                log.action, log.content = local.log_institutionCreate.value, jdata
                tasks.logRecord.delay(log.toJson)
                return tools.genErrorStatusResponse(error.status_200)
        except Exception as e:
            if default.debug:
                print(f"in the institutionUpdateOrCreate create error {e}")
            return tools.genErrorStatusResponse(error.status_foundError)
    else:
        try:
            with transaction.atomic():
                for it in models.InstitutionInfo.objects.filter(institutionid=institutionid):
                    for item in jdata:
                        codename, value = item['codename'], item['value']
                        if not value:
                            default_value = getattr(default, codename, None)
                            if default_value:
                                value = list(default_value.keys())[-1]
                        if codename in {'foundTime'}:
                            setattr(it, codename,
                                    make_aware(datetime.datetime.strptime(value, '%Y-%m-%d')) if value else None)
                        elif codename in {"liaison"}:
                            for x in value:
                                liaison, phone = x['liaison'], x['phone']
                            setattr(it, 'contact', value)
                        elif codename in {'instituionalType', 'institutionalNature', 'operatingStatus'}:
                            if value not in getattr(default, codename):
                                return tools.genErrorStatusResponse(error.status_checkValueError)
                            setattr(it, codename, value)
                        elif codename in {'locate_street', 'locate_county'}:
                            if not value:
                                continue
                            if value != default.defaulNoneInt:
                                setattr(it, codename, models.District.objects.get(ora_index=value))
                        else:
                            setattr(it, codename, value if value else None)
                    it.lastModifier = request.user
                    it.lastTime = now
                    it.save()
                    log.action, log.content = local.log_institutionEdit.value, jdata
                    tasks.logRecord.delay(log.toJson)
                    return tools.genErrorStatusResponse(error.status_200)
                else:
                    return tools.genErrorStatusResponse(error.status_notFound)
        except Exception as e:
            if default.debug:
                print(f"in the institutionUpdateOrCreate update found error {e}  {item}")
            return tools.genErrorStatusResponse(error.status_foundError)


@dbRouter.in_database("subordinate")
def institutionDistrictLevel(request, onlyData=False):
    """
        机构选择地区
    :param request:
    :return:
    """

    def hierarchy(location, concrete=None):
        ds = []
        mx = max(default.belongs.keys()) - 1
        for son in models.District.objects.filter(Q(ora_parent=location) & Q(ora_status=1)).order_by(
                '-ora_weight').iterator():
            dt = tools.BaseData()
            dt.id, dt.name = son.ora_index, son.ora_name
            dt.status = 0
            dt.sub = []
            if concrete:
                conreteid, level = concrete
                if son.ora_level > level:
                    break
                elif son.ora_level == level:
                    if dt.id == conreteid:
                        delattr(dt, 'sub')
                        ds.append(dt.toJson)
                        break
                    else:
                        continue
            if son.ora_level == mx:
                delattr(dt, 'sub')
                ds.append(dt.toJson)
                continue
            for i in hierarchy(son.ora_index):
                dt.sub.append(i)
            if not dt.sub:
                delattr(dt, 'sub')
            ds.append(dt.toJson)
        if not concrete:
            dt = tools.BaseData()
            dt.name, dt.id = default.defaultNoneString, default.defaulNoneInt
            ds.append(dt.toJson)
        return ds

    genre = request.user.groups.all()[0].genre
    dt = tools.BaseData()
    dt.id, dt.name = default.defaultDetailLocations[0], default.defaultDetailLocations[1]
    dt.status = 0
    if genre in {local.super.name, local.systemAdmin.name, local.countyAdmin.name}:
        data = hierarchy(dt.id)
    else:
        data = hierarchy(dt.id, (request.user.locate.ora_index, request.user.locate.ora_level))

    if data:
        dt.sub = data
    if onlyData:
        return [dt.toJson, ]
    else:
        return tools.genErrorStatusResponse(error.status_200, data=[dt.toJson, ])


def institutionBasicForm(request):
    """
        创建机构信息的基础form
    :param request:
    :return:
    """

    def item(key, tp=None):
        dt = tools.BaseData()
        dt.name = getattr(local, "institution_{}".format(key)).value
        dt.codename = key
        dt.choice = []
        if getattr(default, key, None):
            for k, v in getattr(default, key).items():
                item = tools.BaseData()
                item.id = k
                item.name = v
                dt.choice.append(item.toJson)
        dt.value = None
        if not dt.choice:
            delattr(dt, 'choice')
        return dt.toJson

    ds = []
    dt = tools.BaseData()
    dt.name = "基本信息"
    dt.codename = 'a'
    dt.sub = []
    dt.sub.append(item('name'))
    dt.sub.append(item('instituionalType', tp=int))
    dt.sub.append(item('operatingUnit'))
    dt.sub.append(item('operatingStatus', tp=int))
    dt.sub.append(item('institutionalNature', tp=int))
    ds.append(dt.toJson)

    dt = tools.BaseData()
    dt.name = "位置信息"
    dt.codename = 'b'
    dt.sub = []
    x = tools.BaseData()
    x.name = "所在地区"
    x.codename = 'locate'
    x.value = None
    x.choice = institutionDistrictLevel(request, onlyData=True)
    dt.sub.append(x.toJson)
    dt.sub.append(item('address'))
    dt.sub.append(item('latitude'))
    dt.sub.append(item('longitude'))
    dt.sub.append(item('postcode'))
    ds.append(dt.toJson)

    dt = tools.BaseData()
    dt.name = "联系人信息"
    dt.codename = 'c'
    dt.sub = []
    for x in range(6):
        liaison = tools.BaseData()
        liaison.name = None
        liaison.value = None
        liaison.codename = string.ascii_letters[x]
        dt.sub.append(liaison.toJson)
    ds.append(dt.toJson)

    dt = tools.BaseData()
    dt.name = "设施信息"
    dt.codename = 'd'
    dt.sub = []
    dt.sub.append(item('areaCovered'))
    dt.sub.append(item('areaUsed'))
    dt.sub.append(item('numOfBed'))
    dt.sub.append(item('institutionCode'))
    dt.sub.append(item('licenseOfMedical'))
    dt.sub.append(item('licenseOfQualification'))
    dt.sub.append(item('foundTime', tp=time))
    ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds)


def institutionDeleteItem(request):
    """
        删除机构信息
    :param request:
    :return:
    """
    form = requestForms.InstitutionDetail(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    institutionid = form.cleaned_data['institutionid']
    rows = models.InstitutionInfo.objects.filter(institutionid=institutionid).delete()
    if not rows:
        return tools.genErrorStatusResponse(error.status_notFound)
    return tools.genErrorStatusResponse(error.status_200)


def financialCondition(request):
    """
        养老财政投入查询条件
    :param request:
    :return:
    """
    keys = [
        'sourceOfBudget',
        'dateScope'
    ]
    ds: list = []
    for key in keys:
        dt = tools.BaseData()
        atr = "financial_{}".format(key)
        dt.name = getattr(local, atr).value
        dt.codename = key
        dt.conditions = []
        if key == 'sourceOfBudget':
            dt.conditions.append({'key': "全部", "value": None})
        for k, v in getattr(default, key).items():
            x = tools.BaseData()
            x.key = v
            x.value = k
            if key == 'dateScope':
                if k in {1, 2, 3, 4}:
                    x.default = "{};{}".format(*dateScopeProcess(k))
                else:
                    x.default = None
            dt.conditions.append(x.toJson)
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds)


def dateScopeProcess(flag):
    """
        时间处理
    :param flag:
    :return:
    """
    now = make_aware(datetime.datetime.now())
    # 仅12个朋
    if flag == 1:
        st = now - dateutil.relativedelta.relativedelta(months=12)
        ed = now
    # 仅一年
    elif flag == 2:
        st = make_aware(datetime.datetime.strptime("{}-01-01".format(now.year), '%Y-%m-%d'))
        ed = now
    # 仅去年
    elif flag == 3:
        st = make_aware(datetime.datetime.strptime("{}-01-01".format(now.year - 1), '%Y-%m-%d'))
        ed = make_aware(datetime.datetime.strptime("{}-12-31".format(now.year - 1), '%Y-%m-%d'))
    # 近五年
    elif flag == 4:
        st = make_aware(datetime.datetime.strptime("{}-01-01".format(now.year - 4), '%Y-%m-%d'))
        ed = now
    return (st.strftime('%Y-%m'), ed.strftime('%Y-%m'))


def financialQuery(request, baseForm):
    """
        养老财政投入查询条件
    :param request:
    :param baseForm:
    :return:
    """

    def checkid(atr, val):
        for k, v in getattr(default, atr).items():
            if k == val:
                return True
        return False

    keys = [
        'sourceOfBudget',
        'dateScope',
        'customerizedDate',
        'page',
        'size',
        'ed',
        'st',
        "name",
        "content",
        "according"
    ]
    try:
        form = namedtuple('tmp', keys)(ed=None, st=None,
                                       **baseForm.cleaned_data)
    except Exception as e:
        if default.debug:
            print(f"in the financialQuery found  form error {baseForm.cleaned_data} {e}")
        return None, None
    query = Q()
    if form.sourceOfBudget:
        if not checkid("sourceOfBudget", form.sourceOfBudget):
            return None, form
        query &= Q(sourceOfBudget=form.sourceOfBudget)
    if form.dateScope:
        if not checkid('dateScope', form.dateScope):
            return None, form
        now = make_aware(datetime.datetime.now())
        # 仅12个朋
        if form.dateScope == 1:
            st = now - dateutil.relativedelta.relativedelta(months=12)
            ed = now
        # 仅一年
        elif form.dateScope == 2:
            st = make_aware(datetime.datetime.strptime("{}-01-01".format(now.year), '%Y-%m-%d'))
            ed = now
        # 仅去年
        elif form.dateScope == 3:
            st = make_aware(datetime.datetime.strptime("{}-01-01".format(now.year - 1), '%Y-%m-%d'))
            ed = make_aware(datetime.datetime.strptime("{}-12-31".format(now.year - 1), '%Y-%m-%d'))
        # 近五年
        elif form.dateScope == 4:
            st = make_aware(datetime.datetime.strptime("{}-01-01".format(now.year - 4), '%Y-%m-%d'))
            ed = now
        # 自定义
        elif form.dateScope == 5:
            try:
                st_, ed_ = form.customerizedDate.split(';')
                st, ed = make_aware(datetime.datetime.strptime(st_, '%Y-%m')), make_aware(
                    datetime.datetime.strptime(ed_, '%Y-%m'))
            except Exception as e:
                return None, form
        else:
            return None, form
        query &= (Q(expense__ora_date__gte=st) & Q(expense__ora_date__lte=ed))

        form = form._replace(st=st, ed=ed)

    if default.debug:
        print(f"................   in the financialQuery will return {query}")
    return query, form


@dbRouter.in_database("subordinate")
def financialPineChart(request):
    """
        各来源财政投入预算占比统计
    :param request:
    :return:
    """
    form = requestForms.FinancialQueryForm(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    query, form = financialQuery(request, form)
    if not query:
        return tools.genErrorStatusResponse(error.status_checkValueError)
    ds: list = []
    for it in models.Financial.objects.filter(query).distinct().iterator():
        dt = tools.BaseData()
        dt.sourceOfBudget = default.sourceOfBudget[it.sourceOfBudget]
        dt.name = it.name
        dt.expense = 0
        dt.budget = it.budget
        for x in it.expense.all().iterator():
            dt.expense += x.ora_cost
        dt.remainder = it.budget - dt.expense
        dt.remainder = "{:,.2f}".format(dt.remainder)
        dt.expense = "{:,.2f}".format(dt.expense)
        ds.append(dt)
    part = set(map(lambda x: x.sourceOfBudget, ds))
    out = []
    for index, it in enumerate(part):
        dt = tools.BaseData()
        dt.children: list = []
        for x in ds:
            if x.sourceOfBudget == it:
                inner = tools.BaseData()
                inner.name = x.name
                inner.children = []
                inner.children.append({'name': "已支出：{}\n剩余：{}".format(x.expense, x.remainder),
                                       "value": x.budget
                                       })

                dt.children.append(inner.toJson)
        dt.name = it
        dt.codename = string.ascii_letters[index]
        out.append(dt.toJson)
    # 默认值
    if not out:
        out.append({
            "children": [{
                "name": "未定义",
                "children": [{
                    "name": "已支出：0\n剩余：1",
                    "value": 1
                }]
            }],
            "name": "未定义",
            "codename": "a"
        })
    return tools.genErrorStatusResponse(error.status_200, out)


@dbRouter.in_database("subordinate")
def financialHistogramChart(request):
    """
        各来源每月执行金额统计
    :return:
    """
    form = requestForms.FinancialQueryForm(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    query, form = financialQuery(request, form)
    if not query:
        return tools.genErrorStatusResponse(error.status_checkValueError)
    ds: list = []
    part = set()
    for it in models.Financial.objects.filter(query).values('sourceOfBudget', 'expense__ora_date',
                                                            'expense__ora_cost').iterator():
        dt = tools.BaseData()
        dt.sourceOfBudget = it['sourceOfBudget']
        part.add(dt.sourceOfBudget)
        dt.date = it['expense__ora_date'].strftime('%Y-%m') if it['expense__ora_date'] else None
        dt.cost = it['expense__ora_cost']
        ds.append(dt)
    tms = OrderedDict()
    for it in pd.date_range(form.st.strftime("%Y-%m-%d"), form.ed.strftime('%Y-%m-%d')):
        tms[it.strftime('%Y-%m')] = ""
    tms_map = {it: 0 for it in tms}
    out = []
    for index, it in enumerate(part):
        dt = tools.BaseData()
        dt.name = default.sourceOfBudget[it]
        dt.data = []
        for x in ds:
            if x.sourceOfBudget == it:
                if x.date:
                    tms_map[x.date] = x.cost
        dt.data = [*tms_map.values()]
        dt.codename = string.ascii_letters[index]
        out.append(dt.toJson)
    date = [*tms.keys()]
    if not out:
        out.append({
            "name": "未定义",
            "data": [0 for _ in date],
            "codename": "a"
        })
    return tools.genErrorStatusResponse(error.status_200, out, **{'date': date})


@dbRouter.in_database("subordinate")
def financialList(request):
    """
        财政项目列表
    :param request:
    :return:
    """
    form = requestForms.FinancialQueryForm(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    query, form = financialQuery(request, form)

    if query is None:
        return tools.genErrorStatusResponse(error.status_checkValueError)
    try:
        slice_ = tools.getPageSlice(form.size, form.page)
    except Exception:
        return tools.genErrorStatusResponse(error.status_checkValueError)
    ds = []
    total = models.Financial.objects.filter(query).distinct().count()
    for it in models.Financial.objects.filter(query).distinct().order_by('-createTime')[slice_]:
        dt = tools.BaseData()
        dt.name = it.name
        dt.projectid = it.projectid
        dt.budget = "{:,.2f}".format(it.budget) if it.budget else None
        dt.sourceOfBudget = default.sourceOfBudget[it.sourceOfBudget] if it.sourceOfBudget else None
        cost = 0
        if getattr(form, 'st', None):
            for x in it.expense.filter(Q(ora_date__gte=form.st) & Q(ora_date__lte=form.ed)).iterator():
                cost += x.ora_cost
        else:
            for x in it.expense.all().iterator():
                cost += x.ora_cost
        dt.cost = "{:,.2f}".format(cost)
        dt.rate = "{:.2%}".format(cost / it.budget) if all([it.budget, cost]) else '0%'
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds, **{"total": total})


@dbRouter.in_database('subordinate')
def financialDetail(request):
    """
        养老财政投入项目详情
    :param request:
    :return:
    """
    form = requestForms.FinancialDetail(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    projectid = form.cleaned_data['projectid']
    for it in models.Financial.objects.filter(projectid=projectid).iterator():
        dt = tools.BaseData()
        dt.name = it.name
        dt.budget = "{:,.2f}".format(it.budget) if it.budget else None
        dt.sourceOfBudget = default.sourceOfBudget[it.sourceOfBudget]
        dt.content = it.content
        dt.cost = 0
        dt.according = it.according
        dt.createTime = it.createTime.strftime('%Y-%m') if it.createTime else None
        dt.expense = []
        for x in it.expense.all().order_by('ora_date').iterator():
            m = tools.BaseData()
            m.date = x.ora_date.strftime('%Y-%m')
            m.cost = x.ora_cost
            m.rate = "{:.2%}".format(x.ora_cost / it.budget)
            dt.cost += x.ora_cost
            dt.expense.append(m.toJson)
        dt.remainder = it.budget - dt.cost
        tmp_date = [i['date'] for i in dt.expense]
        date_maps = {i.strftime('%Y-%m'): 0 for i in pd.date_range(tmp_date[0], tmp_date[-1])}
        for i in dt.expense:
            date_maps[i['date']] += i['cost']
        dt.costOfTrendMonthly_date = [*date_maps.keys()]
        dt.costOfTrendMonthly_data = [*date_maps.values()]
        return tools.genErrorStatusResponse(error.status_200, dt.toJson)
    else:
        return tools.genErrorStatusResponse(error.status_notFound)


def financialEditDetail(request):
    """
        财政投入项编辑页
    :param request:
    :return:
    """
    form = requestForms.FinancialDetail(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    projectid = form.cleaned_data['projectid']
    for it in models.Financial.objects.filter(projectid=projectid).iterator():
        dt = tools.BaseData()
        dt.name = it.name
        dt.content = it.content
        dt.according = it.according
        dt.sourceOfBudget = it.sourceOfBudget
        dt.sourceOfBudget_conditon = [{'key': v, 'value': k} for k, v in default.sourceOfBudget.items()]
        dt.budget = it.budget
        start = default.financial_begin_date
        end = (datetime.datetime.strptime(start, '%Y-%m-%d') + dateutil.relativedelta.relativedelta(
            years=default.financial_max_date_scope)).strftime('%Y-%m-%d')
        dates = {i.strftime('%Y-%m'): {'cost': None, 'rate': None, 'expenseid': None} for i in
                 pd.date_range(start, end)}
        for x in it.expense.all().iterator():
            date_ = x.ora_date.strftime('%Y-%m')
            cost_ = x.ora_cost
            rate_ = "{:.2%}".format(x.ora_cost / it.budget)
            id_ = x.id
            dates[date_].update(cost=cost_, rate=rate_, expenseid=id_)
        years = set(datetime.datetime.strptime(i, '%Y-%m').year for i in dates)
        ds = []
        for year in years:
            y = tools.BaseData()
            y.year = year
            y.monthData = []
            for mon in range(13)[1:]:
                reps = "{}-{:02}".format(year, mon)
                x = tools.BaseData()
                if reps in dates:
                    x.cost, x.rate, x.expenseid = dates[reps]['cost'], dates[reps]['rate'], dates[reps]['expenseid']
                else:
                    x.cost, x.rate, x.expenseid = None, None, None
                x.date = reps
                y.monthData.append(x.toJson)
            ds.append(y.toJson)
        dt.detail = ds
        return tools.genErrorStatusResponse(error.status_200, dt.toJson)
    else:
        return tools.genErrorStatusResponse(error.status_foundError)


@dbRouter.in_database("subordinate")
def financialDynamicSearch(request):
    """
        养老财政管理动态查询
    :param request:
    :return:
    """
    form = requestForms.FinancialDynamicSearch(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    accroding = form.cleaned_data['according']
    name = form.cleaned_data['name']
    content = form.cleaned_data['content']
    dateScope = form.cleaned_data['dateScope']
    page = form.cleaned_data['page']
    size = form.cleaned_data['size']
    sourceOfBudget = form.cleaned_data['sourceOfBudget']
    tp = form.cleaned_data['type']
    query = Q()
    if tp == 1:
        # 普通搜索
        query |= Q(according__iregex=accroding) if accroding else Q()
        query |= Q(content__iregex=content) if content else Q()
        query |= Q(name__iregex=name) if name else Q()
    else:
        # 高级搜索
        query &= Q(according__iregex=accroding) if accroding else Q()
        query &= Q(content__iregex=content) if content else Q()
        query &= Q(name__iregex=name) if name else Q()
        query &= Q(sourceOfBudget=sourceOfBudget) if sourceOfBudget else Q()
    try:
        if dateScope:
            st, ed = (*map(lambda x: datetime.datetime.strptime(x, '%Y-%m-%d'), dateScope.split(";")),)
            # 高级搜索
            if tp == 2:
                query &= Q(expense__ora_date__gte=make_aware(st)) & Q(
                    expense__ora_date__lt=make_aware(ed + relativedelta.relativedelta(days=1)))
        slice_ = tools.getPageSlice(size, page)
    except Exception as e:
        if default.debug:
            print(f'in the financialDynamicSearch parse parameter error {e}')
        return tools.genErrorStatusResponse(error.status_checkValueError)

    ds: list = []
    total = models.Financial.objects.filter(query).distinct().count()
    for it in models.Financial.objects.filter(query).distinct().order_by('createTime')[slice_]:
        dt = tools.BaseData()
        dt.name = it.name
        dt.projectid = it.projectid
        dt.budget = "{:,.2f}".format(it.budget) if it.budget else None
        dt.sourceOfBudget = default.sourceOfBudget[it.sourceOfBudget] if it.sourceOfBudget else None
        cost = 0
        if getattr(form, 'st', None):
            for x in it.expense.filter(Q(ora_date__gte=form.st) & Q(ora_date__lte=form.ed)).iterator():
                cost += x.ora_cost
        else:
            for x in it.expense.all().iterator():
                cost += x.ora_cost
        dt.cost = "{:,.2f}".format(cost)
        dt.rate = "{:.2%}".format(cost / it.budget) if all([it.budget, cost]) else '0%'
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds, **{"total": total, })


def financialDeleteItem(request):
    """
        删除id
    :param request:
    :return:
    """
    form = requestForms.FinancialDetail(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    projectid = form.cleaned_data['projectid']
    with transaction.atomic():
        for it in models.Financial.objects.filter(projectid=projectid).iterator():
            for x in it.expense.all().iterator():
                x.delete()
            it.delete()
            log = tools.BaseData()
            log.username, log.action, log.content = request.user.username, local.log_deleteFinancialItem.value, form.cleaned_data
            tasks.logRecord.delay(log.toJson)
            return tools.genErrorStatusResponse(error.status_200)
        else:
            return tools.genErrorStatusResponse(error.status_notFound)


def financialUpdateOrCreate(request, created=False):
    """
        财政投入的编辑或新建
    :param request:
    :param created:
    :return:
    """
    form = requestForms.FinancialCreateOrDelete(QueryDict(request.body))
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    changed = form.cleaned_data['changed']
    try:
        jdata = json.loads(changed)
    except Exception as e:
        if default.debug:
            print(f"in the financialUpdateOrCreate check json error {e}")
        return tools.genErrorStatusResponse(error.status_formError)
    # expense.....
    # [{'cost':xxx,'date':'2018-03-02'},]
    # {'name':xxx,'according':xxx,'porjectid':xxx,'content':xxxx,'budget':xxxx,'expense':[{'expenseid':xxx,'date':xxx,'cost':xxx},{'expenseid':xxx,'date':xxx,'cost':xxx}]}
    if created:
        projectid = tools.ID.genUniqueid()
        with transaction.atomic():
            try:
                kwargs = {}
                kwargs['projectid'] = projectid
                kwargs['name'] = jdata['name']
                kwargs['content'] = jdata['content']
                kwargs['according'] = jdata['according']
                kwargs['budget'] = jdata['budget']
                kwargs['sourceOfBudget'] = jdata['sourceOfBudget']
                kwargs['createTime'] = make_aware(datetime.datetime.now())
                obj = models.Financial.objects.create(**kwargs)
                for x in jdata['expense']:
                    obj.expense.add(models.ExpanseRecord.objects.create(ora_cost=x['cost'],
                                                                        ora_date=make_aware(
                                                                            datetime.datetime.strptime(x['date'],
                                                                                                       '%Y-%m'))))
                log = tools.BaseData()
                log.username, log.action, log.content = request.user.username, local.log_createFinancialItem.value, form.cleaned_data
                tasks.logRecord.delay(log.toJson)
                return tools.genErrorStatusResponse(error.status_200)
            except Exception as e:
                if default.debug:
                    print(f"in the financialUpdateOrCreate create error {e}")
                return tools.genErrorStatusResponse(error.status_foundError)
    else:
        with transaction.atomic():
            try:
                projectid = jdata['projectid']
                for it in models.Financial.objects.filter(projectid=projectid):
                    kwargs = {}
                    if jdata['name']:
                        kwargs['name'] = jdata['name']
                    if jdata['content']:
                        kwargs['content'] = jdata['content']
                    if jdata['according']:
                        kwargs['according'] = jdata['according']
                    if jdata['sourceOfBudget']:
                        if jdata['sourceOfBudget'] not in default.sourceOfBudget:
                            return tools.genErrorStatusResponse(error.status_checkValueError)
                        kwargs['sourceOfBudget'] = jdata['sourceOfBudget']
                    if jdata['budget']:
                        kwargs['budget'] = jdata['budget']

                    expense_new = set()
                    for x in jdata['expense']:
                        expenseid, date, cost = x['expenseid'], x['date'], x['cost']
                        for p in it.expense.filter(id=expenseid).iterator():
                            if date:
                                p.ora_date = make_aware(datetime.datetime.strptime(date, '%Y-%m'))
                            if cost:
                                p.ora_cost = cost
                            p.save()
                            expense_new.add(expenseid)
                            break
                        else:
                            expense = models.ExpanseRecord.objects.create(ora_cost=cost,
                                                                          ora_date=make_aware(
                                                                              datetime.datetime.strptime(date,
                                                                                                         '%Y-%m')))
                            it.expense.add(expense)
                            expense_new.add(expense.id)

                    expense_old = set(p.id for p in it.expense.all())
                    for expenseid in expense_old - expense_new:
                        it.expense.filter(id=expenseid).delete()
                    for k, v in kwargs.items():
                        setattr(it, k, v)
                    it.save()
                    log = tools.BaseData()
                    log.username, log.action, log.content = request.user.username, local.log_updateFinancialItem.value, form.cleaned_data
                    tasks.logRecord.delay(log.toJson)
                    return tools.genErrorStatusResponse(error.status_200)
                else:
                    return tools.genErrorStatusResponse(error.status_notFound)
            except Exception as e:
                if default.debug:
                    print(f"in the financialUpdateOrCreate update foud error {e}")
                return tools.genErrorStatusResponse(error.status_foundError)


def FinancialBasicForm(request):
    """
        创建记录时用的
    :param request:
    :return:
    """
    dt = tools.BaseData()
    dt.name = None
    dt.content = None
    dt.according = None
    dt.sourceOfBudget = None
    dt.sourceOfBudget_conditon = [{'key': v, 'value': k} for k, v in default.sourceOfBudget.items()]
    dt.budget = None
    start = default.financial_begin_date
    end = (datetime.datetime.strptime(start, '%Y-%m-%d') + dateutil.relativedelta.relativedelta(
        years=default.financial_max_date_scope)).strftime('%Y-%m-%d')
    dates = {i.strftime('%Y-%m'): {'cost': 0, 'rate': '0'} for i in pd.date_range(start, end)}
    years = set(datetime.datetime.strptime(i, '%Y-%m').year for i in dates)
    ds = []
    for year in years:
        y = tools.BaseData()
        y.year = year
        y.monthData = []
        for mon in range(13)[1:]:
            reps = "{}-{:02}".format(year, mon)
            x = tools.BaseData()
            x.cost, x.rate = None, None
            x.date = reps
            y.monthData.append(x.toJson)
        ds.append(y.toJson)
    dt.detail = ds
    return tools.genErrorStatusResponse(error.status_200, dt.toJson)


@dbRouter.in_database("subordinate")
def policyArticleDistrictLevel(request, districtIds=None, onlyNeed=False, onlySelected=False):
    """
        行政级别
    :param request:
    :return:
    """

    def hierarchy(location, concrete=None):
        ds = []
        mx = max(default.belongs.keys()) - 1
        for son in models.District.objects.filter(Q(ora_parent=location) & Q(ora_status=1)).order_by(
                '-ora_weight').iterator():
            dt = tools.BaseData()
            dt.id, dt.name = son.ora_index, son.ora_name
            dt.status = 0
            dt.canClick = 1 if default_level < son.ora_level else 0
            if districtIds:
                dt.status = 1 if dt.id in districtIds else 0
            dt.sub = []
            if son.ora_level == mx:
                delattr(dt, 'sub')
                if concrete:
                    if concrete == dt.id:
                        ds.append(dt.toJson)
                else:
                    # 查看里的只显示选择地区
                    if onlyNeed:
                        if dt.id in districtIds:
                            ds.append(dt.toJson)
                    else:
                        ds.append(dt.toJson)
                continue
            for i in hierarchy(son.ora_index):
                dt.sub.append(i)
            if not dt.sub:
                delattr(dt, 'sub')
            ds.append(dt.toJson)
        return ds

    dt = tools.BaseData()
    dt.id, dt.name = default.defaultDetailLocations[0], default.defaultDetailLocations[1]
    default_level = default.defaultDetailLocations[2]
    # 有没有被选择
    dt.status = 0
    # 能不能点击
    dt.canClick = 0
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        data = hierarchy(dt.id)
        dt.canClick = 1
    else:
        data = hierarchy(dt.id, concrete=request.user.locate.ora_index if request.user.locate.ora_level == 3 else None)
        dt.canClick = 0 if default_level < request.user.locate.ora_level else 1
    if data:
        dt.sub = data
    if districtIds is not None:
        dt.status = 1 if dt.id in districtIds else 0
        return [dt.toJson, ]
    return tools.genErrorStatusResponse(error.status_200, data=[dt.toJson, ])


def policyArticleUpload(request):
    form = requestForms.ArticleUpload(request.POST, request.FILES)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    filename = form.cleaned_data['filename']
    name, key = tools.downloadFile(filename)
    log = tools.BaseData()
    log.username, log.action, log.content = request.user.username, local.log_policyArticleUploadAccessories.value, str(
        filename)
    tasks.logRecord.delay(log.toJson)
    return tools.genErrorStatusResponse(error.status_200, **{'key': key})


def policyArticleUpdateOrCreate(request, created=False):
    """
        政策文件的发布与编辑
    :param request:
    :param created:
    :return:
    """
    form = requestForms.PolicyArticle(QueryDict(request.body))
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    title = form.cleaned_data['title']
    source = form.cleaned_data['source']
    publishDate = form.cleaned_data['publishDate']
    content = form.cleaned_data['content']
    issuedNumber = form.cleaned_data['issuedNumber']
    accessories = form.cleaned_data['accessories']
    distribution = form.cleaned_data['distribution']
    articleStatus = form.cleaned_data['articleStatus']
    now = make_aware(datetime.datetime.now())
    day: str = now.strftime('%Y-%m-%d')
    sub = os.path.join(settings.ACCESSORIES, day)
    if not os.path.exists(sub):
        os.mkdir(sub)
    uploads = []
    genre = request.user.groups.all()[0].genre
    # accessories格式为'xxxxx;xxxxx;xxxx'
    level = None if genre in {local.systemAdmin.name, local.super.name} else request.user.locate.ora_level
    for it in accessories.split(';'):
        if not it:
            continue
        if '#' in it:
            sub_dir, name = it.split('#')
            glob_path = os.path.join(settings.ACCESSORIES, "{}/{}*".format(sub_dir, name))
            for x in glob.glob(glob_path):
                m = tools.BaseData()
                m.directory = day
                m.key = name
                uploads.append(m.toJson)
        else:
            glob_path = os.path.join(settings.MEDIA_ROOT, "{}*".format(it))
            for x in glob.glob(glob_path):
                shutil.move(x, os.path.join(sub, os.path.basename(x)))
                m = tools.BaseData()
                m.directory = day
                m.key = it
                uploads.append(m.toJson)

    if created:
        try:
            with transaction.atomic():
                kwargs: dict = {}
                articleid = str(tools.ID.genUniqueid())
                kwargs['articleid'] = articleid
                kwargs['title'] = title
                kwargs['source'] = source
                kwargs['publishDate'] = make_aware(datetime.datetime.strptime(publishDate, '%Y-%m-%d'))
                kwargs['content'] = content
                kwargs['issuedNumber'] = issuedNumber
                kwargs['createTime'] = now
                kwargs['lastTime'] = now
                kwargs['articleStatus'] = 1
                kwargs['createdBy'] = request.user
                if uploads:
                    kwargs['accessories'] = json.dumps(uploads)
                obj = models.PolicyArt.objects.create(**kwargs)
                for it in distribution.split(';'):
                    district = models.District.objects.get(ora_index=it)
                    if level and district.ora_level < level:
                        raise Exception("district level .....error ")
                    obj.distribution.add(
                        models.ArtDistribut.objects.create(district=district))
                log = tools.BaseData()
                log.username, log.action, log.content = request.user.username, local.log_policyArticleCreate.value, form.cleaned_data
                tasks.logRecord.delay(log.toJson)
                return tools.genErrorStatusResponse(error.status_200, **{'articleid': articleid})
        except Exception as e:
            if default.debug:
                print(f"in the pollicyArticleUpdateOrCreate create found error {e}")
            return tools.genErrorStatusResponse(error.status_foundError)
    else:
        try:
            with transaction.atomic():
                for it in models.PolicyArt.objects.filter(
                        Q(articleid=form.cleaned_data['articleid']) & Q(articleStatus=1)):
                    if title:
                        it.title = title
                    if content:
                        it.content = content
                    if source:
                        it.source = source
                    if publishDate:
                        it.publishDate = make_aware(datetime.datetime.strptime(publishDate, '%Y-%m-%d'))
                    if issuedNumber:
                        it.issuedNumber = issuedNumber
                    if articleStatus:
                        if articleStatus not in default.articleStatus:
                            raise ValueError('articleStatus error')
                        it.articleStatus = articleStatus
                    if distribution:
                        new_set = set(distribution.split(';'))
                        old_set = set(x.district.id for x in it.distribution.all())
                        for distribut in it.distribution.filter(district__in=(old_set - new_set)):
                            distribut.readers.clear()
                            distribut.delete()

                        for x in new_set - old_set:
                            district = models.District.objects.get(ora_index=x)
                            if level and district.ora_level < level:
                                raise Exception("district level .....error ")
                            it.distribution.add(
                                models.ArtDistribut.objects.create(district=district))
                    jdata = json.loads(it.accessories) if it.accessories else None
                    if jdata:
                        new_set = set(x['key'] for x in uploads)
                        old_set = set(x['key'] for x in jdata)
                        for x in old_set - new_set:
                            for item in jdata[:]:
                                if item['key'] == x:
                                    jdata.remove(item)
                        for x in new_set - old_set:
                            for item in uploads:
                                if item['key'] == x:
                                    jdata.append(item)
                        it.accessories = json.dumps(jdata)
                    else:
                        it.accessories = json.dumps(uploads)
                    log = tools.BaseData()
                    log.username, log.action, log.content = request.user.username, local.log_updatePolicyArticle.value, form.cleaned_data
                    tasks.logRecord.delay(log.toJson)
                    it.save()
                    return tools.genErrorStatusResponse(error.status_200)
                else:
                    return tools.genErrorStatusResponse(error.status_notFound)
        except Exception as e:
            if default.debug:
                print(f"in the pollicyArticleUpdateOrCreate update found error {e}")
            return tools.genErrorStatusResponse(error.status_foundError)


def policyArtDelete(request):
    """
        政策文件删除
    :param request:
    :return:
    """
    form = requestForms.PolicyArticleDelete(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    articleid = form.cleaned_data['articleid']
    with transaction.atomic():
        for item in models.PolicyArt.objects.filter(Q(articleid=articleid) & Q(articleStatus=1)):
            for district in item.distribution.all():
                for reader in district.readers.all():
                    reader.delete()
            if item.accessories:
                jdata = json.loads(item.accessories)
                for x in jdata:
                    directory, key_ = x['directory'], x['key']
                    path = os.path.join(settings.ACCESSORIES, directory)
                    for m in glob.glob("{!s}/{!s}*".format(path, key_)):
                        name = os.path.basename(m)
                        os.unlink("{!s}/{!s}".format(path, name))
            item.delete()
            return tools.genErrorStatusResponse(error.status_200)
        else:
            return tools.genErrorStatusResponse(error.status_notFound)


@dbRouter.in_database("subordinate")
def policyPublishList(request):
    """
        首页最新政策文件列表
    :param request:
    :return:
    """
    form = requestForms.Page(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    page = form.cleaned_data['page']
    size = form.cleaned_data['size']
    ds: list = []
    slice_ = tools.getPageSlice(size, page)
    total = 0
    articleLevel_map = {0: "省消息",
                        1: "市消息",
                        2: "区消息",
                        3: "街道消息",
                        4: "社区消息"}
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        for it in models.PolicyArt.objects.filter(Q(articleStatus=2)).values('title',
                                                                             'source',
                                                                             'issuedNumber',
                                                                             'publishDate',
                                                                             'articleStatus',
                                                                             "content",
                                                                             'createdBy__locate__ora_level',
                                                                             'articleid').order_by('-publishDate')[
            slice_]:
            dt = tools.BaseData()
            dt.title = it['title']
            dt.source = it['source']
            dt.issuedNumber = it['issuedNumber']
            dt.publishDate = it['publishDate'].strftime("%Y-%m-%d")
            dt.articleid = it['articleid']
            dt.articleStatus = it['articleStatus']
            dt.content = it['content']
            dt.articleLevel = articleLevel_map[it['createdBy__locate__ora_level']] if it[
                                                                                          'createdBy__locate__ora_level'] and \
                                                                                      it[
                                                                                          'createdBy__locate__ora_level'] in articleLevel_map else "全区消息"
            ds.append(dt.toJson)
        total = models.PolicyArt.objects.filter(Q(articleStatus__in={2, })).count()
    else:
        for it in models.PolicyArt.objects.filter(
                Q(distribution__district__ora_index=request.user.locate.ora_index) & Q(articleStatus=2)).values('title',
                                                                                                                'source',
                                                                                                                'issuedNumber',
                                                                                                                'publishDate',
                                                                                                                'articleStatus',
                                                                                                                "content",
                                                                                                                'createdBy__locate__ora_level',
                                                                                                                'articleid').order_by(
            '-publishDate')[
            slice_]:
            dt = tools.BaseData()
            dt.title = it['title']
            dt.source = it['source']
            dt.issuedNumber = it['issuedNumber']
            dt.publishDate = it['publishDate'].strftime("%Y-%m-%d")
            dt.articleid = it['articleid']
            dt.content = it['content']
            dt.articleStatus = it['articleStatus']
            dt.articleLevel = articleLevel_map[it['createdBy__locate__ora_level']] if it[
                                                                                          'createdBy__locate__ora_level'] and \
                                                                                      it[
                                                                                          'createdBy__locate__ora_level'] in articleLevel_map else "全区消息"
            ds.append(dt.toJson)
        total = models.PolicyArt.objects.filter(
            Q(distribution__district__ora_index=request.user.locate.ora_index) & Q(articleStatus=2)).count()

    return tools.genErrorStatusResponse(error.status_200, ds, **{'total': total})


@dbRouter.in_database("subordinate")
def policyArticleList(request):
    """
        政策文件列表
    :param request:
    :return:
    """
    form = requestForms.Page(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    page = form.cleaned_data['page']
    size = form.cleaned_data['size']
    ds: list = []
    slice_ = tools.getPageSlice(size, page)
    total = 0
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        for it in models.PolicyArt.objects.values('title', 'source',
                                                  'issuedNumber',
                                                  'articleStatus',
                                                  'publishDate', 'articleid').order_by('-createTime')[slice_]:
            dt = tools.BaseData()
            dt.title = it['title']
            dt.source = it['source']
            dt.issuedNumber = it['issuedNumber']
            dt.publishDate = it['publishDate'].strftime("%Y-%m-%d")
            dt.articleid = it['articleid']
            dt.articleStatus = it['articleStatus']
            ds.append(dt.toJson)
        total = models.PolicyArt.objects.count()
    else:
        users = request.user.locate.webuser_set.all()
        for it in \
                models.PolicyArt.objects.filter(Q(articleStatus__in={1, 2, 3}) & Q(createdBy__in=users)).values(
                    'title',
                    'source',
                    'issuedNumber',
                    'publishDate',
                    'articleStatus',
                    'articleid').order_by(
                    '-createTime')[
                    slice_]:
            dt = tools.BaseData()
            dt.title = it['title']
            dt.source = it['source']
            dt.issuedNumber = it['issuedNumber']
            dt.publishDate = it['publishDate'].strftime("%Y-%m-%d")
            dt.articleid = it['articleid']
            dt.articleStatus = it['articleStatus']
            ds.append(dt.toJson)
        total = models.PolicyArt.objects.filter(
            Q(distribution__district__ora_index=request.user.locate.ora_index) & Q(articleStatus__in={1, 2, 3}) & Q(
                createdBy=request.user)).count()

    return tools.genErrorStatusResponse(error.status_200, ds, **{'total': total})


@dbRouter.in_database("subordinate")
def policyArticlePreview(request, detail=False, editPage=False):
    """
        文件预览
    :param request:
    :return:
    """

    def scanRecursion(ds: list):
        ret = []
        for it in ds:
            if 'status' in it and it['status']:
                ret.append(it['name'])
            if 'sub' in it:
                for x in scanRecursion(it['sub']):
                    ret.append(x)
        return ret

    def getAccessories(data: list):
        """
            获取对应的附件名
        :param data:
        :return:
        """
        ds = []
        for it in json.loads(data):
            directory, key = it['directory'], it['key']
            path = os.path.join(settings.ACCESSORIES, directory)
            for x in glob.glob("{!s}/{!s}*".format(path, key)):
                name = os.path.basename(x)
                name = name.split(key)[1]
                dt = tools.BaseData()
                dt.name = name
                dt.key = "{!s}#{!s}".format(directory, key)
                ds.append(dt.toJson)
        return ds

    form = requestForms.PolicyArticlePreview(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    articleid = form.cleaned_data['articleid']
    # 政策管理页的
    policyManaged = form.cleaned_data['policyManaged']
    for it in models.PolicyArt.objects.filter(articleid=articleid):
        dt = tools.BaseData()
        dt.title = it.title
        dt.content = it.content
        if editPage:
            districtIds = set()
            for item in it.distribution.all():
                districtIds.add(item.district.ora_index)
            districtLevel = policyArticleDistrictLevel(request, districtIds)
            dt.districtLevel = districtLevel
        else:
            districtIds = set()
            for item in it.distribution.all():
                districtIds.add(item.district.ora_index)
            districtLevel = policyArticleDistrictLevel(request, districtIds, onlyNeed=True)
            dt.districtLevel = scanRecursion(districtLevel)
        dt.source = it.source
        dt.publishDate = it.publishDate.strftime('%Y-%m-%d') if it.publishDate else None
        dt.issuedNumber = it.issuedNumber
        dt.accessories = getAccessories(it.accessories) if it.accessories else None
        if detail:
            tasks.policyArticleStatistic.delay(request.user.username, articleid)

        return tools.genErrorStatusResponse(error.status_200, dt.toJson)
    else:
        return tools.genErrorStatusResponse(error.status_notFound)


@dbRouter.in_database("subordinate")
def policyDownloadAccessories(request, deleteAction=False):
    """
        政制文件附件下载
    :param request:
    :return:
    """
    form = requestForms.PolicyDownloadAccessories(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    articleid = form.cleaned_data['articleid']
    key = form.cleaned_data['key']
    for it in models.PolicyArt.objects.filter(articleid=articleid).values('accessories'):
        if it['accessories']:
            jdata = json.loads(it['accessories'])
            for x in jdata:
                directory, key_ = x['directory'], x['key']
                if "{!s}#{!s}".format(directory, key_) == key:
                    path = os.path.join(settings.ACCESSORIES, directory)
                    for m in glob.glob("{!s}/{!s}*".format(path, key_)):
                        try:
                            name = os.path.basename(m)
                            if deleteAction:
                                os.unlink("{!s}/{!s}".format(path, name))
                                return 'ok'
                            response = downloadServer(request, path="{!s}/{!s}".format(directory, name),
                                                      document_root=settings.ACCESSORIES)
                            response['Content-Disposition'] = "attachment; filename={!s}".format(
                                escape_uri_path(name.split(key_)[1]))
                            return response
                        except Exception as e:
                            if default.debug:
                                print(f"in the policyDownloadAccessories found error {e}")
                            return HttpResponse("found error ....")
                    break
    else:
        return HttpResponse("not found ...")


def policyArticlePublish(request):
    """
        文件发布
    :param request:
    :return:
    """
    form = requestForms.PolicyArticlePreview(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    articleid = form.cleaned_data['articleid']
    # 发布id
    status = 2
    for it in models.PolicyArt.objects.filter(articleid=articleid).exclude(articleStatus=2):
        # 地区隐藏的话,删除它
        for district in it.distribution.filter(district__ora_status=0):
            district.readers.clear()
            district.delete()
        it.articleStatus = status
        it.save()
        log = tools.BaseData()
        log.username, log.action, log.content = request.user.username, local.log_publishPolicyArticle.value, form.cleaned_data
        tasks.logRecord.delay(log.toJson)
        return tools.genErrorStatusResponse(error.status_200)
    else:
        return tools.genErrorStatusResponse(error.status_notFound)


def policyArticleRevocation(request):
    """
        发布的政策文件撤回
    :param request:
    :return:
    """
    form = requestForms.PolicyArticlePreview(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    articleid = form.cleaned_data['articleid']
    # 撤回id
    status = 3
    rows = models.PolicyArt.objects.filter(articleid=articleid).exclude(articleStatus=status).update(
        articleStatus=status)
    if not rows:
        return tools.genErrorStatusResponse(error.status_notFound)
    log = tools.BaseData()
    log.username, log.action, log.content = request.user.username, local.log_policyArticleRevocation.value, form.cleaned_data
    tasks.logRecord.delay(log.toJson)
    return tools.genErrorStatusResponse(error.status_200)


def policyArticleDetail(request):
    """
        政策文件查看
    :param request:
    :return:
    """
    return policyArticlePreview(request, detail=True)


def policyArticleEditPage(request):
    """
        政策文件编辑页
    :param request:
    :return:
    """
    return policyArticlePreview(request, detail=False, editPage=True)


@dbRouter.in_database("subordinate")
def policyDynamicSearch(request, managed=False):
    """
        政策文件动态查询
    :param request:
    :param managed: 管理页的请求处理
    :return:
    """
    form = requestForms.PolicyDynamic(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    title = form.cleaned_data['title']
    source = form.cleaned_data['source']
    publishDate = form.cleaned_data['publishDate']
    content = form.cleaned_data['content']
    issuedNumber = form.cleaned_data['issuedNumber']
    accessories = form.cleaned_data['accessories']
    page = form.cleaned_data['page']
    size = form.cleaned_data['size']
    tp = form.cleaned_data['type']

    query = Q()
    genre = request.user.groups.all()[0].genre
    if tp == 1:
        # 普通搜索
        query |= Q(title__icontains=title) if title else Q()
        query |= Q(source__icontains=source) if source else Q()
        query |= Q(issuedNumber__icontains=issuedNumber) if issuedNumber else Q()
    else:
        # 高级搜索
        query &= Q(content__iregex=content) if content else Q()
        query &= Q(issuedNumber__icontains=issuedNumber) if issuedNumber else Q()
        query &= Q(accessories__icontains=accessories) if accessories else Q()
        query &= Q(title__icontains=title) if title else Q()
        query &= Q(source__icontains=source) if source else Q()

    if genre in {local.super.name, local.systemAdmin.name}:
        pass
    else:
        # 高级搜索
        if managed:
            query &= Q(articleStatus__in={1, 2, 3})
            if genre in {local.super.countyAdmin.name}:
                query &= Q(createdBy__in=request.user.locate.webuser_set.all())
            else:
                query &= Q(createdBy=request.user)
        else:
            query &= Q(articleStatus=2)
            query &= Q(distribution__district__in={request.user.locate, })

    try:
        slice_ = tools.getPageSlice(size, page)
        if publishDate:
            st, ed = (*map(lambda x: datetime.datetime.strptime(x, '%Y-%m-%d'), publishDate.split(';')),)
            if 0 <= (ed - st).total_seconds():
                pass
            else:
                raise Exception("in the policyDynamic parse datetime error")
            if tp == 2:
                query &= Q(publishDate__gte=make_aware(st)) & Q(
                    publishDate__lt=make_aware(ed + relativedelta.relativedelta(days=1)))
    except Exception as e:
        if default.debug:
            print(f"in the policyDynamic parse error {e}")
        return tools.genErrorStatusResponse(error.status_checkValueError)
    ds: list = []
    if default.debug:
        print(f"in the policyDynamicSearch the query is {query}")
    total = models.PolicyArt.objects.filter(query).count()
    for it in \
            models.PolicyArt.objects.filter(query).values(
                'title',
                'source',
                'issuedNumber',
                'publishDate',
                'articleStatus',
                "content",
                'articleid').order_by(
                '-createTime')[
                slice_]:
        dt = tools.BaseData()
        dt.title = it['title']
        dt.source = it['source']
        dt.issuedNumber = it['issuedNumber']
        dt.publishDate = it['publishDate'].strftime("%Y-%m-%d")
        dt.articleid = it['articleid']
        dt.articleStatus = it['articleStatus']
        dt.content = it['content']
        ds.append(dt.toJson)
    return tools.genErrorStatusResponse(error.status_200, ds, **{'total': total})


def pollicyAccessoriesDelete(request):
    """
        附件文件删除
    :param request:
    :return:
    """
    ret = policyDownloadAccessories(request, deleteAction=True)
    if ret == 'ok':
        return tools.genErrorStatusResponse(error.status_200)
    return tools.genErrorStatusResponse(error.status_foundError)


@dbRouter.in_database("subordinate")
def policyArticleChart(request):
    """
        政策文件统计围标信息
    :param request:
    :return:
    """
    form = requestForms.PolicyArticlePreview(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    articleid = form.cleaned_data['articleid']
    for article in models.PolicyArt.objects.prefetch_related('distribution').filter(articleid=articleid):
        dt = tools.BaseData()
        dt.totalDistrict = 0
        dt.readDistrict = 0
        dt.waitforDistrict = 0
        dt.countyReaders = 0
        dt.streetReaders = 0
        dt.otherReaders = 0
        dt.totalReaders = 0
        for district in article.distribution.prefetch_related('readers').all().iterator():
            dt.totalDistrict += 1
            haveReaders = False
            for reader in district.readers.prefetch_related('user__locate').all().iterator():
                if not getattr(reader.user, 'locate', None):
                    dt.otherReaders += 1
                else:
                    # 区级人员
                    if reader.user.locate.ora_level == 2:
                        dt.countyReaders += 1
                    # 街道/乡镇人员
                    elif reader.user.locate.ora_level == 3:
                        dt.streetReaders += 1
                    else:
                        dt.otherReaders += 1
                haveReaders = True
            if haveReaders:
                dt.readDistrict += 1
        dt.waitforDistrict = dt.totalDistrict - dt.readDistrict
        dt.totalReaders = dt.countyReaders + dt.streetReaders + dt.otherReaders
        return tools.genErrorStatusResponse(error.status_200, dt.toJson)
    else:
        return tools.genErrorStatusResponse(error.status_notFound)


@dbRouter.in_database("subordinate")
def policyArticleStatisticList(request):
    """
        政策文件人员阅读情况
    :param request:
    :return:
    """
    form = requestForms.PolicyArticleStatisticList(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    articleid = form.cleaned_data['articleid']
    try:
        slice_ = tools.getPageSlice(form.cleaned_data['size'], form.cleaned_data['page'])
    except Exception:
        return tools.genErrorStatusResponse(error.status_formError)
    users_list = []
    total = models.ArtReader.objects.filter(artdistribut__policyart__articleid=articleid).count()
    for reader in models.ArtReader.objects.filter(artdistribut__policyart__articleid=articleid)[slice_]:
        user = tools.BaseData()
        user.username = reader.user.username if reader.user else None
        user.firstTime = reader.firstTIme.strftime('%Y-%m-%d %H:%M %S')
        user.lastTime = reader.lastTime.strftime('%Y-%m-%d %H:%M %S')
        user.readTimes = reader.times
        user.belong = ' '.join([*reversed(getBelong(reader.user.locate.ora_index))]) if getattr(reader.user, 'locate',
                                                                                                None) else None
        users_list.append(user.toJson)
    return tools.genErrorStatusResponse(error.status_200, users_list, **{'total': total})


def dataMapElderPosition(request, *args, **kwargs):
    """
        老人位置地图
    :param request:
    :param args:
    :param kwargs:
    :return:
    """
    form = requestForms.ElderPosition(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    default_pageSize = 10000
    try:
        slice_ = tools.getPageSlice(default_pageSize, form.cleaned_data['page'])
    except Exception:
        return tools.genErrorStatusResponse(error.status_formError)
    if default.elderPosition_cacheKey not in cache:
        tasks.elderPosition_lngAndlat_cache.delay()
    data = cache.get(default.elderPosition_cacheKey, None)
    ret = []
    if data:
        total = data["total"]
        lng_lat_data = data["data"]
        for item in lng_lat_data[slice_]:
            tmp = tools.BaseData()
            tmp.lng, tmp.lat, tmp.count = float(item[0]), float(item[1]), item[2]
            ret.append(tmp.toJson)
    if ret:
        return tools.genErrorStatusResponse(error.status_200, ret, **{'pageSize': default_pageSize, "total": total})
    return tools.genErrorStatusResponse(error.status_notFound)


def institutionMapPosition(request, typeSet, pageSize):
    """
        机构养老地图/机构列表
    :param request:
    :param instituionalType: 1:照料中心,2:养老机构,3:养老驿站
    :return:
    """
    form = requestForms.ElderPosition(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    try:
        slice_ = tools.getPageSlice(pageSize, form.cleaned_data['page'])
    except Exception as e:
        return tools.genErrorStatusResponse(error.status_formError)
    ret = []
    total = models.InstitutionInfo.objects.filter(
        Q(instituionalType__in=typeSet) & Q(operatingStatus__in={1, 3})).count()
    for it in \
            models.InstitutionInfo.objects.filter(
                Q(instituionalType__in=typeSet) & Q(operatingStatus=1) & Q(longitude__isnull=False)).values(
                "longitude",
                "numOfBed",
                "name",
                "address",
                "contact",
                'latitude')[
                slice_].__iter__():
        tmp = tools.BaseData()
        tmp.lng = it['longitude']
        tmp.lat = it["latitude"]
        tmp.name = it['name']
        tmp.contact = first(None, ast.literal_eval(it['contact'])) if it['contact'] else None
        tmp.address = it['address']
        tmp.numOfBed = it["numOfBed"]
        ret.append(tmp.toJson)
    if ret:
        return tools.genErrorStatusResponse(error.status_200, ret, **{"pageSize": pageSize, "total": total})
    return tools.genErrorStatusResponse(error.status_notFound)


def homeGetActivities(request):
    """
        首页活动图片获取
    :param request:
    :return:
    """
    files = [
        {"descritpion": "2019丰台区深化推进全国居家和社区养老...", "pic": "1.jpg"},
        {"descritpion": "丰台区退役军人信息采集及悬挂光荣牌...", "pic": "2.jpg"},
        {"descritpion": "情系基层，把百姓需求放首位------北...", "pic": "3.jpg"}
    ]
    path = os.path.join(settings.STATICFILES_DIRS[0], 'pics')
    files_ret: list = []
    for item in files:
        path_ = os.path.join(path, item["pic"])
        if os.path.exists(path_):
            cnt = tools.BaseData()
            cnt.description = item["descritpion"]
            cnt.url = "{}pics/{}".format(settings.STATIC_URL, item["pic"])
            files_ret.append(cnt.toJson)
    return tools.genErrorStatusResponse(error.status_200, files_ret)


def callCenterRecordList(request: HttpRequest):
    """
        获取呼叫记录
    :param request:
    :return:
    """
    form = requestForms.ElderPosition(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)

    try:
        slice_ = tools.getPageSlice(form.cleaned_data['size'], form.cleaned_data['page'])
    except Exception as e:
        return tools.genErrorStatusResponse(error.status_formError)
    result: list = []
    total = models.CallCenter.objects.count()
    for item in models.CallCenter.objects.all().order_by('-service_begin')[slice_]:
        data = tools.BaseData()
        data.service_date = item.service_date.strftime("%Y-%m-%d") if item.service_date else ''
        data.customer_name = item.customer_name
        data.service_item = item.service_item_name
        data.service_content = item.service_content
        data.waiter_name = item.waiter_name
        data.recordid = item.id
        result.append(data.toJson)
    return tools.genErrorStatusResponse(error.status_200, result, **{"total": total, })


def callcenterRecordDetail(request: HttpRequest):
    """
        呼叫中心详情
    :param request:
    :return:
    """
    form = requestForms.CallCenterRecord(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    recordid = form.cleaned_data['recordid']
    for item in models.CallCenter.objects.filter(id=recordid):
        result: dict = model_to_dict(item)
        result['service_date'] = result['service_date'].strftime("%Y-%m-%d") if result['service_date'] else ''
        result['service_begin'] = result['service_begin'].strftime("%Y-%m-%d %H:%M:%S") if result[
            'service_begin'] else ''
        result['service_end'] = result['service_end'].strftime("%Y-%m-%d %H:%M:%S") if result['service_end'] else ''
        result['actual_begin'] = result['actual_begin'].strftime("%Y-%m-%d %H:%M:%S") if result['actual_begin'] else ''
        result['actual_end'] = result['actual_end'].strftime("%Y-%m-%d %H:%M:%S") if result['actual_end'] else ''
        result['visit_date'] = result['visit_date'].strftime("%Y-%m-%d %H:%M:%S") if result['visit_date'] else ''
        return tools.genErrorStatusResponse(error.status_200, result)
    return tools.genErrorStatusResponse(error.status_notFound)


def callcenterDynamicSearch(request: HttpRequest):
    """
        呼叫中心动态搜索
    :param request:
    :return:
    """
    form = requestForms.CallCenterDynamicSearch(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    customer_name = form.cleaned_data['customer_name']
    customer_phone = form.cleaned_data['customer_phone']
    identity_no = form.cleaned_data['identity_no']
    # xxxx-xx-xx;xxxx-xx-xx格式
    service_date = form.cleaned_data['service_date']
    service_item_name = form.cleaned_data['service_item_name']
    service_content = form.cleaned_data['service_content']
    waiter_name = form.cleaned_data['waiter_name']
    waiter_phone = form.cleaned_data['waiter_phone']
    station_name = form.cleaned_data['station_name']
    ty = form.cleaned_data['type']
    query = Q()

    # 普通搜索
    if ty == 1:
        query |= Q(customer_name__icontains=customer_name)
        query |= Q(customer_phone__icontains=customer_phone)
        query |= Q(identity_no__icontains=identity_no)
    # 高级搜索
    elif ty == 2:
        query &= Q(customer_name__icontains=customer_name) if customer_name else Q()
        query &= Q(customer_phone__icontains=customer_phone) if customer_phone else Q()
        query &= Q(identity_no__icontains=identity_no) if identity_no else Q()
        query &= Q(service_item_name__icontains=service_item_name) if service_item_name else Q()
        query &= Q(service_content__icontains=service_content) if service_content else Q()
        query &= Q(waiter_name__icontains=waiter_name) if waiter_name else Q()
        query &= Q(waiter_phone__icontains=waiter_phone) if waiter_phone else Q()
        query &= Q(station_name__icontains=station_name) if station_name else Q()
        if service_date:
            try:
                begin, end = [make_aware(datetime.datetime.strptime(date, '%Y-%m-%d')) for date in
                              service_date.split(';')]
            except Exception as e:
                return tools.genErrorStatusResponse(error.status_checkValueError)
            query &= Q(service_date__gte=begin)
            query &= Q(service_date__lte=end)
    else:
        return tools.genErrorStatusResponse(error.status_checkValueError)
    try:
        slice_ = tools.getPageSlice(form.cleaned_data['size'], form.cleaned_data['page'])
    except Exception as e:
        return tools.genErrorStatusResponse(error.status_formError)
    result: list = []
    total = models.CallCenter.objects.filter(query).count()
    for item in models.CallCenter.objects.filter(query).order_by('-service_date')[slice_]:
        data = tools.BaseData()
        data.service_date = item.service_date.strftime("%Y-%m-%d") if item.service_date else ''
        data.customer_name = item.customer_name
        data.service_item = item.service_item_name
        data.service_content = item.service_content
        data.waiter_name = item.waiter_name
        data.recordid = item.id
        result.append(data.toJson)
    return tools.genErrorStatusResponse(error.status_200, result, **{"total": total, })


def exportCallcenterData(request: HttpRequest):
    """
        呼叫中心数据导出
    :param request:
    :return:
    """
    form = requestForms.ExportElderData(request.POST)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    format = form.cleaned_data['format']
    scope = form.cleaned_data['scope']
    query = json.loads(form.cleaned_data['query'])
    # 全部数据
    if int(scope) == 2:
        resultid = "export_all_data_of_callcenter"
        if resultid in cache:
            return tools.genErrorStatusResponse(error.status_200, {'taskid': resultid})
    # 查询条件下的数据
    elif int(scope) == 1:
        query_form = requestForms.OlderInfo(query)
        if not query_form.is_valid():
            return tools.genErrorStatusResponse(error.status_formError)
        content = "{}_{}_{}".format(format, scope, json.dumps(query))
        resultid = tools.getMD5(content)
        if resultid in cache:
            return tools.genErrorStatusResponse(error.status_200, {'taskid': resultid})
    cache.set(resultid, {"state": "PENDING", "taskid": None}, timeout=3600)
    tasks.conrtollerCallCenter_private.apply_async(
        kwargs={'format': format, 'scope': scope, 'query': query, 'cacheid': resultid})
    return tools.genErrorStatusResponse(error.status_200, {'taskid': resultid})
