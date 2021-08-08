###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for pcs FEDORA-2018-57bbe74c6c
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.874369");
  script_version("2021-06-08T02:00:22+0000");
  script_tag(name:"last_modification", value:"2021-06-08 02:00:22 +0000 (Tue, 08 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-04-19 08:55:01 +0200 (Thu, 19 Apr 2018)");
  script_cve_id("CVE-2018-1086", "CVE-2018-1079");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for pcs FEDORA-2018-57bbe74c6c");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcs'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"pcs on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"FEDORA", value:"2018-57bbe74c6c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IFV7OMJDCU77BZ2X3C6SH3QVGAQLCM5R");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC27");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"pcs", rpm:"pcs~0.9.164~1.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
