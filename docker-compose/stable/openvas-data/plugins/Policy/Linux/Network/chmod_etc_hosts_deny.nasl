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
  script_oid("1.3.6.1.4.1.25623.1.0.150090");
  script_version("2021-03-03T15:26:07+0000");
  script_tag(name:"last_modification", value:"2021-03-03 15:26:07 +0000 (Wed, 03 Mar 2021)");
  script_tag(name:"creation_date", value:"2020-01-20 11:55:34 +0100 (Mon, 20 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: SSH /etc/hosts.deny chmod");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_etc_hosts_deny.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"644", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/hosts_access");

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 3.3.5 Ensure permissions on /etc/hosts.deny are configured (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 5.1 Establish Secure Configurations");

  script_tag(name:"summary", value:"The access control software consults two files. The search stops
at the first match:

  - Access will be granted when a (daemon, client) pair matches an entry in the /etc/hosts.allow file.

  - Otherwise, access will be denied when a (daemon, client) pair matches an entry in the /etc/hosts.deny file.

  - Otherwise, access will be granted.

A non-existing access control file is treated as if it were an empty file. Thus, access control can
be turned off by providing no access control files.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "stat /etc/hosts.deny";
title = "chmod /etc/hosts.deny";
solution = "chmod PERMISSION /etc/hosts.deny";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux/etc/hosts_deny/stat/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not get information about /etc/hosts.deny";
}else{
  stat = get_kb_item("Policy/linux/etc/hosts_deny/stat");
  value = policy_get_access_permissions(stat:stat);
  compliant = policy_access_permissions_match_or_stricter(value:value, set_point:default);
  comment = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
