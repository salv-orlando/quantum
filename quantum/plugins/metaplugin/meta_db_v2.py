# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from sqlalchemy.orm import exc

import quantum.db.api as db
from quantum.plugins.metaplugin import meta_models_v2


def get_flavor_by_network(net_id):
    session = db.get_session()
    try:
        binding = (session.query(meta_models_v2.Flavor).
                   filter_by(network_id=net_id).
                   one())
    except exc.NoResultFound:
        return None
    return binding.flavor


def add_flavor_binding(flavor, net_id):
    session = db.get_session()
    binding = meta_models_v2.Flavor(flavor=flavor, network_id=net_id)
    session.add(binding)
    session.flush()
    return binding
