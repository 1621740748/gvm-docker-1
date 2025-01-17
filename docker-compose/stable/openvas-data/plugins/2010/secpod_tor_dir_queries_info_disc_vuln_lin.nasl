###############################################################################
# OpenVAS Vulnerability Test
#
# Tor Directory Queries Information Disclosure Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902101");
  script_version("2020-10-20T15:03:35+0000");
  script_tag(name:"last_modification", value:"2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0383", "CVE-2010-0385");
  script_bugtraq_id(37901);
  script_name("Tor Directory Queries Information Disclosure Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38198");
  script_xref(name:"URL", value:"http://archives.seul.org/or/talk/Jan-2010/msg00162.html");
  script_xref(name:"URL", value:"http://archives.seul.org/or/announce/Jan-2010/msg00000.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_tor_detect_lin.nasl");
  script_mandatory_keys("Tor/Linux/Ver");

  script_tag(name:"affected", value:"Tor version prior to 0.2.1.22 and 0.2.2.x before 0.2.2.7-alpha on Linux.");

  script_tag(name:"insight", value:"The issue is due to bridge directory authorities disclosing all tracked
  bridge identities when responding to 'dbg-stability.txt' directory queries.");

  script_tag(name:"solution", value:"Upgrade to version 0.2.1.22 or later.");

  script_tag(name:"summary", value:"This host is installed with Tor and is prone to Information Disclosure
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive information
  that can help them launch further attacks.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

torVer = get_kb_item("Tor/Linux/Ver");
if(!torVer){
  exit(0);
}

torVer = ereg_replace(pattern:"-", replace:".", string:torVer);
if(version_is_less(version:torVer, test_version:"0.2.1.22")){
  security_message(port:0);
  exit(0);
}

if(torVer =~ "^0\.2\.2\." && version_is_less(version:torVer, test_version:"0.2.2.7.alpha")) {
  security_message(port:0);
  exit(0);
}
