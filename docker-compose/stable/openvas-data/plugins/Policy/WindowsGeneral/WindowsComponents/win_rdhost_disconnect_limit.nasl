# Copyright (C) 2018 Greenbone Networks GmbH
#
# Text descriptions excerpted from a referenced source are
# Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.109473");
  script_version("2019-12-13T11:11:18+0000");
  script_tag(name:"last_modification", value:"2019-12-13 11:11:18 +0000 (Fri, 13 Dec 2019)");
  script_tag(name:"creation_date", value:"2018-06-27 13:00:52 +0200 (Wed, 27 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: Time limit for disconnected sessions (Remote Desktop Services)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Maximum", type:"entry", value:"60000");

  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting allows you to configure a time limit for
disconnected Remote Desktop Services sessions.

You can use this policy setting to specify the maximum amount of time that a disconnected session
remains active on the server. By default, Remote Desktop Services allows users to disconnect from a
Remote Desktop Services session without logging off and ending the session.

When a session is in a disconnected state, running programs are kept active even though the user is
no longer actively connected. By default, these disconnected sessions are maintained for an
unlimited time on the server.

If you enable this policy setting, disconnected sessions are deleted from the server after the
specified amount of time. To enforce the default behavior that disconnected sessions are maintained
for an unlimited time, select Never. If you have a console session, disconnected session time limits
do not apply.

If you disable or do not configure this policy setting, this policy setting is not specified at the
Group Policy level. Be y default, Remote Desktop Services disconnected sessions are maintained for
an unlimited amount of time.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Set time limit for disconnected sessions";
solution = "Set following UI path accordingly:
Windows Components/Remote Desktop Services/Remote Desktop Session Host/Session Time Limits/" + title;
type = "HKLM";
key = "Software\Policies\Microsoft\Windows NT\Terminal Services";
item = "MaxDisconnectionTime";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Maximum");

if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else
  results = policy_min_max_reg_dword(key:key, item:item, type:type, default:default, min:FALSE,
    max:TRUE, not_zero:TRUE, as_sz:TRUE);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
