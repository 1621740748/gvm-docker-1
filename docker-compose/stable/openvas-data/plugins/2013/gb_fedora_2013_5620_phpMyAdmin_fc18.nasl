###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for phpMyAdmin FEDORA-2013-5620
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.865580");
  script_version("2021-07-02T02:00:36+0000");
  script_tag(name:"last_modification", value:"2021-07-02 02:00:36 +0000 (Fri, 02 Jul 2021)");
  script_tag(name:"creation_date", value:"2013-04-25 10:16:53 +0530 (Thu, 25 Apr 2013)");
  script_cve_id("CVE-2013-1937");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-11 02:29:00 +0000 (Mon, 11 Feb 2019)");
  script_name("Fedora Update for phpMyAdmin FEDORA-2013-5620");
  script_xref(name:"FEDORA", value:"2013-5620");
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2013-April/103184.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpMyAdmin'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC18");
  script_tag(name:"affected", value:"phpMyAdmin on Fedora 18");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"phpMyAdmin", rpm:"phpMyAdmin~3.5.8~1.fc18", rls:"FC18")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
