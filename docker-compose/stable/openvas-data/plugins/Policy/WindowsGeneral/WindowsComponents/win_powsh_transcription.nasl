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
  script_oid("1.3.6.1.4.1.25623.1.0.109498");
  script_version("2021-02-12T07:37:42+0000");
  script_tag(name:"last_modification", value:"2021-02-12 07:37:42 +0000 (Fri, 12 Feb 2021)");
  script_tag(name:"creation_date", value:"2018-06-28 08:37:05 +0200 (Thu, 28 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Microsoft Windows: PowerShell Transcription");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"0;1");

  script_xref(name:"Policy", value:"CIS Microsoft Windows 10 Enterprise (Release 2004) Benchmark v1.9.1: 18.9.95.2 (L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'");
  script_xref(name:"Policy", value:"CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark v1.1.0: 18.9.95.2 (L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 5.1 Establish Secure Configurations");
  script_xref(name:"URL", value:"https://www.microsoft.com/en-us/download/confirmation.aspx?id=25250");

  script_tag(name:"summary", value:"This policy setting lets you capture the input and output of
Windows PowerShell commands into text-based transcripts.

If you enable this policy setting, Windows PowerShell will enable transcripting for Windows
PowerShell, the Windows PowerShell ISE, and any other applications that leverage the Windows
PowerShell engine. By default, Windows PowerShell will record transcript output to each users' My
Documents directory, with a file name that includes 'PowerShell_transcript', along with the computer
name and time started. Enabling this policy is equivalent to calling the Start-Transcript cmdlet on
each Windows PowerShell session.

If you disable this policy setting, transcripting of PowerShell-based applications is disabled by
default, although transcripting can still be enabled through the Start-Transcript cmdlet.

If you use the OutputDirectory setting to enable transcript logging to a shared location, be sure to
limit access to that directory to prevent users from viewing the transcripts of other users or
computers.

(C) Microsoft Corporation 2015.");

  exit(0);
}

include("smb_nt.inc");
include("policy_functions.inc");
include("host_details.inc");
include("version_func.inc");

target_os = "Microsoft Windows 7 or later";
win_min_ver = "6.1";
title = "Turn on PowerShell Transcription";
solution = "Set following UI path accordingly:
Windows Components/Windows PowerShell/" + title;
type = "HKLM";
key = "Software\Policies\Microsoft\Windows\PowerShell\Transcription";
item = "EnableTranscripting";
reg_path = type + "\" + key + "!" + item;
test_type = "RegKey";
default = script_get_preference("Value");

if(!policy_verify_win_ver(min_ver:win_min_ver))
  results = policy_report_wrong_os(target_os:target_os);
else
  results = policy_match_exact_reg_dword(key:key, item:item, type:type, default:default);

value = results["value"];
comment = results["comment"];
compliant = results["compliant"];

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:reg_path, info:comment);
policy_set_kbs(type:test_type, cmd:reg_path, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
