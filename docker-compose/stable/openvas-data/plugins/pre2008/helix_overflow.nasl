# OpenVAS Vulnerability Test
# Description: Helix RealServer Buffer Overrun
#
# Authors:
# Keith Young
#
# Copyright:
# Copyright (C) 2003 Montgomery County Maryland Government Security Team
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11642");
  script_version("2020-11-10T09:46:51+0000");
  script_tag(name:"last_modification", value:"2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(8476);
  script_cve_id("CVE-2003-0725");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Helix RealServer Buffer Overrun");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Montgomery County Maryland Government Security Team");
  script_family("Gain a shell remotely");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 554);
  script_mandatory_keys("RTSP/server_banner/available");

  script_tag(name:"solution", value:"Install patches from the vendor.");

  script_tag(name:"summary", value:"RealServer 8.0 and earlier and Helix Server 9.0 is
  vulnerable to a buffer overflow vulnerability.");

  script_xref(name:"URL", value:"http://service.real.com/help/faq/security/bufferoverrun030303.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:554, proto:"rtsp");

serverbanner = get_kb_item("RTSP/" + port + "/server_banner");
if(!serverbanner || "Version " >!< serverbanner)
  exit(0);

# Currently, all versions up to and including 9.0.1 are affected
if((egrep(pattern:"Version [0-8]\.[0-9]", string:serverbanner)) || (egrep(pattern:"Version 9\.0\.[01]", string:serverbanner)) ) {
  security_message(port:port);
  exit(0);
}

exit(99);
