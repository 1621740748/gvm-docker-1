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
  script_oid("1.3.6.1.4.1.25623.1.0.150060");
  script_version("2020-11-12T10:09:08+0000");
  script_tag(name:"last_modification", value:"2020-11-12 10:09:08 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-01-10 10:33:06 +0100 (Fri, 10 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Check options for /var directory");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("linux_list_mounted_filesystems.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Options", type:"entry", value:"nodev,nosuid,noexec", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/8/mount");

  script_tag(name:"summary", value:"The /var directory is used by the system during an operation.

This script tests options set on /var filesystem.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "mount | grep /var";
title = "Mount options on /var";
solution = "mount -o remount,[OPTIONS] /var";
test_type = "SSH_Cmd";
default = script_get_preference("Options", id:1);

if(get_kb_item("linux/mount/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not get information about partitions";
}else{
  value = get_kb_item("linux/mount//var/options");
  compliant = policy_settings_list_in_value(value:value, set_points:default, sep:",");
  comment = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);