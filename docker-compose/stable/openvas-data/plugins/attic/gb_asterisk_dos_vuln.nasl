###############################################################################
# OpenVAS Vulnerability Test
#
# Asterisk Open Source and Certified Asterisk RTP Resource Exhaustion Denial of Service Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.107148");
  script_version("2020-11-25T09:16:10+0000");
  script_tag(name:"last_modification", value:"2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)");
  script_tag(name:"creation_date", value:"2017-04-18 10:44:46 +0200 (Tue, 18 Apr 2017)");
  script_cve_id("CVE-2016-7551");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Asterisk Open Source and Certified Asterisk RTP Resource Exhaustion Denial of Service Vulnerability");

  script_tag(name:"summary", value:"DEPRECATED since this check is already covered in 'Asterisk RTP Resource
  Exhaustion Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.106239)

  Asterisk Open Source and Certified Asterisk are prone to a remote denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The overlap dialing feature in chan_sip allows chan_sip to report to
  a device that the number that has been dialed is incomplete and more digits are required. If this functionality
  is used with a device that has performed username/password authentication RTP resources are leaked. This occurs
  because the code fails to release the old RTP resources before allocating new ones in this scenario. If all
  resources are used then RTP port exhaustion will occur and no RTP sessions are able to be set up.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause a denial-of-service condition.");

  script_tag(name:"affected", value:"The following products and versions are vulnerable:

  Digium Asterisk 13 before 13.11.1

  Digium Asterisk 11 before 11.23.1

  Digium Certified Asterisk 13 before 13.8-cert3

  Digium Certified Asterisk 11 before 11.6-cert1");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92888");
  script_xref(name:"URL", value:"https://downloads.asterisk.org/pub/security/AST-2016-007.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");

  script_tag(name:"deprecated", value: TRUE);

  exit(0);
}

exit(66);
