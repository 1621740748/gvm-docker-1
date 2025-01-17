###############################################################################
# OpenVAS Vulnerability Test
#
# Pidgin MXit Message Parsing Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803102");
  script_version("2020-10-20T15:03:35+0000");
  script_cve_id("CVE-2012-3374");
  script_bugtraq_id(54322);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2012-10-19 13:10:50 +0530 (Fri, 19 Oct 2012)");
  script_name("Pidgin MXit Message Parsing Buffer Overflow Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49831/");
  script_xref(name:"URL", value:"http://hg.pidgin.im/pidgin/main/rev/ded93865ef42");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/index.php?id=64");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a stack-based buffer
  overflow via a specially crafted RX message which may lead to the execution
  of arbitrary code in the context of the application or to denial-of-service.");
  script_tag(name:"affected", value:"Pidgin version prior to 2.10.5 on Windows");
  script_tag(name:"insight", value:"A boundary error within the 'mxit_show_message()' function, when parsing
  incoming instant messages containing inline images.");
  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.10.5 or later.");
  script_tag(name:"summary", value:"This host has installed with Pidgin and is prone to buffer
  overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(pidginVer)
{
  if(version_is_less(version:pidginVer, test_version:"2.10.5")){
    report = report_fixed_ver(installed_version:pidginVer, fixed_version:"2.10.5");
    security_message(port:0, data:report);
  }
}
