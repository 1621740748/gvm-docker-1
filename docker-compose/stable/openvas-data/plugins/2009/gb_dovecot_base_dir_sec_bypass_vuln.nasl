###############################################################################
# OpenVAS Vulnerability Test
#
# Description: Dovecot 'base_dir' Insecure Permissions Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801055");
  script_version("2020-08-14T08:58:27+0000");
  script_tag(name:"last_modification", value:"2020-08-14 08:58:27 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3897");
  script_bugtraq_id(37084);
  script_name("Dovecot 'base_dir' Insecure Permissions Security Bypass Vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54363");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3306");
  script_xref(name:"URL", value:"http://www.dovecot.org/list/dovecot-news/2009-November/000143.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"impact", value:"Successful attack could allow malicious people to log in as another user,
  which may aid in further attacks.");

  script_tag(name:"affected", value:"Dovecot versions 1.2 before 1.2.8.");

  script_tag(name:"insight", value:"This flaw is due to insecure permissions (0777) being set on the 'base_dir'
  directory and its parents, which could allow malicious users to replace auth
  sockets and log in as other users.");

  script_tag(name:"solution", value:"Apply the patch or upgrade to Dovecot version 1.2.8.");

  script_tag(name:"summary", value:"This host has Dovecot installed and is prone to Security Bypass
  Vulnerability.");

  exit(0);
}

CPE = "cpe:/a:dovecot:dovecot";

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^1\.2" && version_is_less(version: version, test_version: "1.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
