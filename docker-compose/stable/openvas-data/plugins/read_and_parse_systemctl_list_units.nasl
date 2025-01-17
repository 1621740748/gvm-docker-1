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
  script_oid("1.3.6.1.4.1.25623.1.0.150170");
  script_version("2020-12-16T14:37:19+0000");
  script_tag(name:"last_modification", value:"2020-12-16 14:37:19 +0000 (Wed, 16 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-03-17 14:57:24 +0000 (Tue, 17 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Read sysctemctl services (KB)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("gather-package-list.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://man7.org/linux/man-pages/man1/systemctl.1.html");

  script_tag(name:"summary", value:"systemctl may be used to introspect and control the state of the
'systemd' system and service manager. Please refer to systemd for an introduction into the basic
concepts and functionality this tool manages.

list-units: List units that systemd currently has in memory. This includes units that are either
referenced directly or through a dependency, units that are pinned by applications programmatically,
or units that were active in the past and have failed. By default only units which are active, have
pending jobs, or have failed are shown.

Note: This script only stores information for other Policy Controls.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

if(!get_kb_item("login/SSH/success") || !sock = ssh_login_or_reuse_connection()){
  set_kb_item(name:"Policy/linux/systemctl/ssh/ERROR", value:TRUE);
  exit(0);
}

cmd = "systemctl --no-pager --no-legend list-unit-files 2>/dev/null";
ret = ssh_cmd_without_errors(socket:sock, cmd:cmd);
if(!ret){
  set_kb_item(name:"Policy/linux/systemctl/ERROR", value:TRUE);
  exit(0);
}

foreach row (split(ret, keep:FALSE)){
  match = eregmatch(string:row, pattern:"([^.]+)\.([a-z,A-Z]+)\s+(.+)");
  if(match){
    name = chomp(match[1]);
    type = chomp(match[2]);
    status = ereg_replace(string:chomp( match[3] ), pattern:"^.+(\s+)$", replace:"");

    set_kb_item(name:"Policy/linux/systemctl/" + name + "/" + type, value:status);
  }
}

exit(0);