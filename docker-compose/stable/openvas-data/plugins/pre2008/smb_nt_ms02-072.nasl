###############################################################################
# OpenVAS Vulnerability Test
#
# Unchecked Buffer in XP Shell Could Enable System Compromise (329390)
#
# Authors:
# Michael Scheidell SECNAP Network Security
#
# Copyright:
# Copyright (C) 2002 SECNAP Network Security, LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11194");
  script_version("2020-06-09T11:16:08+0000");
  script_tag(name:"last_modification", value:"2020-06-09 11:16:08 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(6427);
  script_cve_id("CVE-2002-1327");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Unchecked Buffer in XP Shell Could Enable System Compromise (329390)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 SECNAP Network Security, LLC");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"It is possible for a malicious user to mount a buffer
  overrun attack using windows XP shell.");

  script_tag(name:"impact", value:"A successful attack could have the effect of either causing
  the Windows Shell to fail, or causing an attacker's code to run on
  the user's computer in the security context of the user.");

  script_tag(name:"affected", value:"Microsoft Windows XP.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-072");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(xp:2) <= 0 ) exit(0);
if ( hotfix_missing(name:"Q329390") > 0 )
  security_message(port:0);
