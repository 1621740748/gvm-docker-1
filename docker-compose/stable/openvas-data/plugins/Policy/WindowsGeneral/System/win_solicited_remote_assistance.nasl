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
  script_oid("1.3.6.1.4.1.25623.1.0.109543");
  script_version("2021-02-08T13:41:11+0000");
  script_tag(name:"last_modification", value:"2021-02-08 13:41:11 +0000 (Mon, 08 Feb 2021)");
  script_tag(name:"creation_date", value:"2018-08-07 14:04:55 +0200 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("Microsoft Windows: Configure Solicited Remote Assistance");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"0;1");

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 18.8.36.2 (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 18.8.36.2 (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 5.1 Establish Secure Configurations");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting allows you to turn on or turn off Solicited
(Ask for) Remote Assistance on this computer.

If you enable this policy setting, users on this computer can use email or file transfer to ask
someone for help. Also, users can use instant messaging programs to allow connections to this
computer, and you can configure additional Remote Assistance settings.

If you disable this policy setting, users on this computer cannot use email or file transfer to ask
someone for help. Also, users cannot use instant messaging programs to allow connections to this
computer.

If you do not configure this policy setting, users can turn on or turn off Solicited (Ask for)
Remote Assistance themselves in System Properties in Control Panel. Users can also configure Remote
Assistance settings.

(C) 2015 Microsoft Corporation.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("version_func.inc");

target_os = "Microsoft Windows 8.1 or later";
win_min_ver = "6.3";
title = "Configure Solicited Remote Assistance";
solution = "Set following UI path accordingly:
Computer Configuration/Administrative Templates/System/Remote Assistance/" + title;
test_type = "RegKey";
type = "HKLM";
key = "Software\policies\Microsoft\Windows NT\Terminal Services";
item = "fAllowToGetHelp";
reg_path = type + "\" + key + "!" + item;
default = script_get_preference("Value");

if(!policy_verify_win_ver(min_ver:win_min_ver)){
  results = policy_report_wrong_os(target_os:target_os);
}else{
  results = policy_match_exact_reg_dword(key:key, item:item, type:type, default:default);
}

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);