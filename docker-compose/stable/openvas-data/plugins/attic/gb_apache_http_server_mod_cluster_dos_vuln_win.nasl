###############################################################################
# OpenVAS Vulnerability Test
#
# Apache HTTP Server 'mod_cluster' Denial of Service Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812579");
  script_version("2020-11-12T10:28:08+0000");
  script_cve_id("CVE-2016-8612");
  script_bugtraq_id(94939);
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-11-12 10:28:08 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2018-03-21 11:34:53 +0530 (Wed, 21 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache HTTP Server 'mod_cluster' Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running Apache HTTP Server
  and is prone to denial of service vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in protocol
  parsing logic of mod_cluster load balancer Apache HTTP Server modules that
  allows attacker to cause a Segmentation Fault in the serving httpd process.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service condition.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.23 on Windows.");

  script_tag(name:"solution", value:"See the vendor advisory for a solution.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1387605");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=57169");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web Servers");

  # This is a Redhat vulnerability (mod_cluster) and not in Apache itself
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
