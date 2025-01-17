###############################################################################
# OpenVAS Vulnerability Test
#
# DM FileManager 'album.php' Remote File Inclusion Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800836");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2399");
  script_bugtraq_id(35521);
  script_name("DM FileManager 'album.php' Remote File Inclusion Vulnerability");
  script_category(ACT_MIXED_ATTACK); # unknown why the safe_checks below was used
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dm_filemanager_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dm-filemanager/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35622");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35521/exploit");
  script_xref(name:"URL", value:"http://www.dutchmonkey.com/?label=Latest+News+%26+Announcements#20090704");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker execute arbitrary PHP
  code, and can include arbitrary file from local or external resources when register_globals is enabled.");

  script_tag(name:"affected", value:"DutchMonkey, DM FileManager version 3.9.4 and prior.");

  script_tag(name:"insight", value:"Error exists when input passed to the 'SECURITY_FILE' parameter in 'album.php'
  in 'dm-albums/template/' directory is not properly verified before being used to include files.");

  script_tag(name:"solution", value:"Apply the security patch from the references.");

  script_tag(name:"summary", value:"The host is running DM FileManager and is prone to a remote file
  inclusion vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

cpe_list = make_list("cpe:/a:dutchmonkey:dm_filemanager",
                     "cpe:/a:dutchmonkey:dm_album");

if(!infos = get_app_port_from_list(cpe_list:cpe_list))
  exit(0);

cpe = infos["cpe"];
port = infos["port"];

if(!infos = get_app_version_and_location(cpe:cpe, port:port, exit_no_version:FALSE))
  exit(0);

vers = infos["version"];
path = infos["location"];
install_path = path;

if("dm_album" >< cpe)
  is_dm_album = TRUE;

if(path && !safe_checks()) {

  if(path == "/")
    path = "";

  files = traversal_files();

  foreach pattern(keys(files)) {

    file = files[pattern];

    # nb: path should already have the "/dm-albums" or "/albums" path found by gb_dm_filemanager_detect.nasl
    if(is_dm_album)
      url = path + "/template/album.php?SECURITY_FILE=/" + file;
    else
      url = path + "/dm-albums/template/album.php?SECURITY_FILE=/" + file;

    if(http_vuln_check(port:port, url:url, pattern:pattern)) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

if(!vers)
  exit(0);

if(!is_dm_album && version_is_less_equal(version:vers, test_version:"3.9.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:install_path);
  security_message(port:port, data:report);
  exit(0);
}

if(is_dm_album && version_is_less(version:vers, test_version:"1.9.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references", install_path:install_path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
