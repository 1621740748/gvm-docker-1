# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.150240");
  script_version("2021-07-31T11:19:19+0000");
  script_tag(name:"last_modification", value:"2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-05-14 07:32:07 +0000 (Thu, 14 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Disabling the Telnet Service");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("vrp_telnet_server_status.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("huawei/vrp/yunshan/detected");

  script_tag(name:"summary", value:"The Telnet login mode is insecure.");

  exit(0);
}

include("policy_functions.inc");

if(!cmd = get_kb_item("Policy/vrp/current_configuration/telnet_status/cmd"))
  cmd = "display telnet server; display telnet server status";

title = "Disabling the Telnet Service";
solution = "Run the undo telnet server enable and undo telnet ipv6 server enable commands to disable
the Telnet service.";
test_type = "SSH_Cmd";
default = "Disable";

if(get_kb_item("Policy/vrp/installed/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No VRP device detected.";
}else if(get_kb_item("Policy/vrp/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to VRP device.";
}else if(get_kb_item("Policy/vrp/current_configuration/telnet_status/major_version/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine version of device.";
}else if(get_kb_item("Policy/vrp/current_configuration/telnet_status/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine the current telnet service status.";
}else{
  telnetserver = get_kb_item("Policy/vrp/current_configuration/telnet_status/telnetserver");
  telnetipv4server = get_kb_item("Policy/vrp/current_configuration/telnet_status/telnetipv4server");
  telnetipv6server = get_kb_item("Policy/vrp/current_configuration/telnet_status/telnetipv6server");
  if(tolower(telnetserver) == "enable" ||
     tolower(telnetipv4server) == "enable" ||
     tolower(telnetipv6server) == "enable")
    value = "Enable";
  else
    value = "Disable";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
