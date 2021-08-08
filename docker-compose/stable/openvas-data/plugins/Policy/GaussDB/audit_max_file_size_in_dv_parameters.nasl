# Copyright (C) 2020 Greenbone Networks GmbH
#
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.150216");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-04-15 14:37:07 +0000 (Wed, 15 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("ZSQL: Maximum Capacity of an Audit Log File");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("zsql_dv_parameters.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"10M", id:1);

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"The parameter _AUDIT_MAX_FILE_SIZE specifies the maximum
capacity of an audit log file. The default unit is byte and the default value is 10M. If the size of
an audit log file reaches the specified value, another audit log file is automatically created.");

  exit(0);
}

include("policy_functions.inc");

cmd = "SELECT NAME,VALUE FROM DV_PARAMETERS WHERE NAME = '_AUDIT_MAX_FILE_SIZE';";
title = "Maximum Capacity of an Audit Log File";
solution = "Change the value of _AUDIT_MAX_FILE_SIZE in ${GSDB_DATA}/cfg/zengine.ini, or run
'ALTER SYSTEM SET _AUDIT_MAX_FILE_SIZE = 10M;'";
test_type = "SQL_Query";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/zsql/dv_parameters/ssh/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/zsql/dv_parameters/ERROR")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not read table DV_PARAMETERS";
}else if(!value = get_kb_item("Policy/zsql/dv_parameters/_AUDIT_MAX_FILE_SIZE/value")){
  compliant = "incomplete";
  value = "error";
  comment = "Can not find value for _AUDIT_MAX_FILE_SIZE in table DV_PARAMETERS";
}else{
  compliant = policy_setting_min_match(value:value, set_point:default);
}

policy_reporting(result:value, default:">= " + default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
