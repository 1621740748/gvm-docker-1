# Copyright (C) 2020 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150189");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-04-02 17:39:49 +0000 (Thu, 02 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("GaussDB: Access permissions to ${GSDB_HOME}/add-ons");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_gsdb_home_permissions.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"700", id:1);

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");

  script_tag(name:"summary", value:"The {GSDB_HOME}/lib and {GSDB_HOME}/add-ons directories store
GaussDB 100 shared components.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "stat ${GSDB_HOME}/add-ons";
title = "Access permissions to ${GSDB_HOME}/add-ons";
solution = "chmod PERMISSION ${GSDB_HOME}/add-ons";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux/gaussdb/${GSDB_HOME}/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host possible";
}else if(get_kb_item("Policy/linux/${GSDB_HOME}/add-ons/stat/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not get information about ${GSDB_HOME}/add-ons";
}else{
  stat = get_kb_item("Policy/linux/${GSDB_HOME}/add-ons/stat");
  value = policy_get_access_permissions(stat:stat);
  compliant = policy_access_permissions_match_or_stricter(value:value, set_point:default);
  grep_file = egrep(string:stat, pattern:"File:");
  file = eregmatch(string:grep_file, pattern:"File:[^/]+([a-z,A-Z,_,/,-,.,0-9]*)");
  comment = "File: " + file[1];
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
