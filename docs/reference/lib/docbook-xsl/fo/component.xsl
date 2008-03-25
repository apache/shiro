<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:fo="http://www.w3.org/1999/XSL/Format"
                version='1.0'>

<!-- ********************************************************************
     $Id: component.xsl,v 1.1 2003/03/27 23:07:17 turin42 Exp $
     ********************************************************************

     This file is part of the XSL DocBook Stylesheet distribution.
     See ../README or http://nwalsh.com/docbook/xsl/ for copyright
     and other information.

     ******************************************************************** -->

<!-- ==================================================================== -->

<xsl:template name="component.title">
  <xsl:param name="node" select="."/>
  <xsl:param name="pagewide" select="0"/>
  <xsl:variable name="id">
    <xsl:call-template name="object.id">
      <xsl:with-param name="object" select="$node"/>
    </xsl:call-template>
  </xsl:variable>
  <xsl:variable name="title">
    <xsl:apply-templates select="$node" mode="object.title.markup">
      <xsl:with-param name="allow-anchors" select="1"/>
    </xsl:apply-templates>
  </xsl:variable>
  <xsl:variable name="titleabbrev">
    <xsl:apply-templates select="$node" mode="titleabbrev.markup"/>
  </xsl:variable>

  <xsl:if test="$passivetex.extensions != 0">
    <fotex:bookmark xmlns:fotex="http://www.tug.org/fotex"
                    fotex-bookmark-level="2"
                    fotex-bookmark-label="{$id}">
      <xsl:value-of select="$titleabbrev"/>
    </fotex:bookmark>
  </xsl:if>

  <fo:block keep-with-next.within-column="always"
            space-before.optimum="{$body.font.master}pt"
            space-before.minimum="{$body.font.master * 0.8}pt"
            space-before.maximum="{$body.font.master * 1.2}pt"
            hyphenate="false">
    <xsl:if test="$pagewide != 0">
      <xsl:attribute name="span">all</xsl:attribute>
    </xsl:if>
    <xsl:copy-of select="$title"/>
  </fo:block>
</xsl:template>

<!-- ==================================================================== -->

<xsl:template match="dedication" mode="dedication">
  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

  <xsl:variable name="master-reference">
    <xsl:call-template name="select.pagemaster"/>
  </xsl:variable>

  <fo:page-sequence id="{$id}"
                    hyphenate="{$hyphenate}"
                    master-reference="{$master-reference}">
    <xsl:attribute name="language">
      <xsl:call-template name="l10n.language"/>
    </xsl:attribute>
    <xsl:attribute name="format">
      <xsl:call-template name="page.number.format"/>
    </xsl:attribute>
    <xsl:choose>
      <xsl:when test="not(preceding::chapter
                          or preceding::preface
                          or preceding::appendix
                          or preceding::article
                          or preceding::dedication
                          or parent::part
                          or parent::reference)">
        <!-- if there is a preceding component or we're in a part, the -->
        <!-- page numbering will already be adjusted -->
        <xsl:attribute name="initial-page-number">1</xsl:attribute>
      </xsl:when>
      <xsl:when test="$double.sided != 0">
        <xsl:attribute name="initial-page-number">auto-odd</xsl:attribute>
      </xsl:when>
    </xsl:choose>

    <xsl:apply-templates select="." mode="running.head.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <xsl:apply-templates select="." mode="running.foot.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <fo:flow flow-name="xsl-region-body">
      <xsl:call-template name="dedication.titlepage"/>
      <xsl:apply-templates/>
    </fo:flow>
  </fo:page-sequence>
</xsl:template>

<xsl:template match="dedication"></xsl:template> <!-- see mode="dedication" -->
<xsl:template match="dedication/docinfo"></xsl:template>
<xsl:template match="dedication/title"></xsl:template>
<xsl:template match="dedication/subtitle"></xsl:template>
<xsl:template match="dedication/titleabbrev"></xsl:template>

<!-- ==================================================================== -->

<xsl:template match="colophon">
  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

  <xsl:variable name="master-reference">
    <xsl:call-template name="select.pagemaster"/>
  </xsl:variable>

  <fo:page-sequence id="{$id}"
                    hyphenate="{$hyphenate}"
                    master-reference="{$master-reference}">
    <xsl:attribute name="language">
      <xsl:call-template name="l10n.language"/>
    </xsl:attribute>
    <xsl:attribute name="format">
      <xsl:call-template name="page.number.format"/>
    </xsl:attribute>
    <xsl:if test="$double.sided != 0">
      <xsl:attribute name="initial-page-number">auto-odd</xsl:attribute>
    </xsl:if>

    <xsl:apply-templates select="." mode="running.head.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <xsl:apply-templates select="." mode="running.foot.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <fo:flow flow-name="xsl-region-body">
      <xsl:call-template name="colophon.titlepage"/>
      <xsl:apply-templates/>
    </fo:flow>
  </fo:page-sequence>
</xsl:template>

<xsl:template match="colophon/title"></xsl:template>
<xsl:template match="colophon/subtitle"></xsl:template>
<xsl:template match="colophon/titleabbrev"></xsl:template>

<!-- ==================================================================== -->

<xsl:template match="preface">
  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

  <xsl:variable name="master-reference">
    <xsl:call-template name="select.pagemaster"/>
  </xsl:variable>

  <fo:page-sequence id="{$id}"
                    hyphenate="{$hyphenate}"
                    master-reference="{$master-reference}">
    <xsl:attribute name="language">
      <xsl:call-template name="l10n.language"/>
    </xsl:attribute>
    <xsl:attribute name="format">
      <xsl:call-template name="page.number.format"/>
    </xsl:attribute>

    <!-- Page numbering for a preface doesn't restart; it continues from the ToC -->
    <xsl:if test="$double.sided != 0">
      <xsl:attribute name="initial-page-number">auto-odd</xsl:attribute>
    </xsl:if>

    <xsl:apply-templates select="." mode="running.head.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <xsl:apply-templates select="." mode="running.foot.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <fo:flow flow-name="xsl-region-body">
      <xsl:call-template name="preface.titlepage"/>

      <xsl:variable name="toc.params">
        <xsl:call-template name="find.path.params">
          <xsl:with-param name="table" select="normalize-space($generate.toc)"/>
        </xsl:call-template>
      </xsl:variable>
      <xsl:if test="contains($toc.params, 'toc')">
        <xsl:call-template name="component.toc"/>
        <xsl:call-template name="component.toc.separator"/>
      </xsl:if>

      <xsl:apply-templates/>
    </fo:flow>
  </fo:page-sequence>
</xsl:template>

<xsl:template match="preface/docinfo|prefaceinfo"></xsl:template>
<xsl:template match="preface/title"></xsl:template>
<xsl:template match="preface/titleabbrev"></xsl:template>
<xsl:template match="preface/subtitle"></xsl:template>

<!-- ==================================================================== -->

<xsl:template match="chapter">
  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

  <xsl:variable name="master-reference">
    <xsl:call-template name="select.pagemaster"/>
  </xsl:variable>

  <fo:page-sequence id="{$id}"
                    hyphenate="{$hyphenate}"
                    master-reference="{$master-reference}">
    <xsl:attribute name="language">
      <xsl:call-template name="l10n.language"/>
    </xsl:attribute>
    <xsl:attribute name="format">
      <xsl:call-template name="page.number.format"/>
    </xsl:attribute>
    <xsl:choose>
      <xsl:when test="not(preceding::chapter
                          or preceding::appendix
                          or preceding::article
                          or preceding::dedication
                          or parent::part
                          or parent::reference)">
        <!-- if there is a preceding component or we're in a part, the -->
        <!-- page numbering will already be adjusted -->
        <xsl:attribute name="initial-page-number">1</xsl:attribute>
      </xsl:when>
      <xsl:when test="$double.sided != 0">
        <xsl:attribute name="initial-page-number">auto-odd</xsl:attribute>
      </xsl:when>
    </xsl:choose>

    <xsl:apply-templates select="." mode="running.head.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <xsl:apply-templates select="." mode="running.foot.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <fo:flow flow-name="xsl-region-body">
      <xsl:call-template name="chapter.titlepage"/>

      <xsl:variable name="toc.params">
        <xsl:call-template name="find.path.params">
          <xsl:with-param name="table" select="normalize-space($generate.toc)"/>
        </xsl:call-template>
      </xsl:variable>
      <xsl:if test="contains($toc.params, 'toc')">
        <xsl:call-template name="component.toc"/>
        <xsl:call-template name="component.toc.separator"/>
      </xsl:if>
      <xsl:apply-templates/>
    </fo:flow>
  </fo:page-sequence>
</xsl:template>

<xsl:template match="chapter/docinfo|chapterinfo"></xsl:template>
<xsl:template match="chapter/title"></xsl:template>
<xsl:template match="chapter/titleabbrev"></xsl:template>
<xsl:template match="chapter/subtitle"></xsl:template>

<!-- ==================================================================== -->

<xsl:template match="appendix">
  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

  <xsl:variable name="master-reference">
    <xsl:call-template name="select.pagemaster"/>
  </xsl:variable>

  <fo:page-sequence id="{$id}"
                    hyphenate="{$hyphenate}"
                    master-reference="{$master-reference}">
    <xsl:attribute name="language">
      <xsl:call-template name="l10n.language"/>
    </xsl:attribute>
    <xsl:attribute name="format">
      <xsl:call-template name="page.number.format"/>
    </xsl:attribute>
    <xsl:choose>
      <xsl:when test="not(preceding::chapter
                          or preceding::appendix
                          or preceding::article
                          or preceding::dedication
                          or parent::part
                          or parent::reference)">
        <!-- if there is a preceding component or we're in a part, the -->
        <!-- page numbering will already be adjusted -->
        <xsl:attribute name="initial-page-number">1</xsl:attribute>
      </xsl:when>
      <xsl:when test="$double.sided != 0">
        <xsl:attribute name="initial-page-number">auto-odd</xsl:attribute>
      </xsl:when>
    </xsl:choose>

    <xsl:apply-templates select="." mode="running.head.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <xsl:apply-templates select="." mode="running.foot.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <fo:flow flow-name="xsl-region-body">
      <xsl:call-template name="appendix.titlepage"/>

      <xsl:variable name="toc.params">
        <xsl:call-template name="find.path.params">
          <xsl:with-param name="table" select="normalize-space($generate.toc)"/>
        </xsl:call-template>
      </xsl:variable>

      <xsl:if test="contains($toc.params, 'toc')">
        <xsl:call-template name="component.toc"/>
        <xsl:call-template name="component.toc.separator"/>
      </xsl:if>
      <xsl:apply-templates/>
    </fo:flow>
  </fo:page-sequence>
</xsl:template>

<xsl:template match="appendix/docinfo|appendixinfo"></xsl:template>
<xsl:template match="appendix/title"></xsl:template>
<xsl:template match="appendix/titleabbrev"></xsl:template>
<xsl:template match="appendix/subtitle"></xsl:template>

<!-- ==================================================================== -->

<xsl:template match="article">
  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

  <xsl:variable name="master-reference">
    <xsl:call-template name="select.pagemaster"/>
  </xsl:variable>

  <fo:page-sequence id="{$id}"
                    hyphenate="{$hyphenate}"
                    master-reference="{$master-reference}">
    <xsl:attribute name="language">
      <xsl:call-template name="l10n.language"/>
    </xsl:attribute>
    <xsl:attribute name="format">
      <xsl:call-template name="page.number.format"/>
    </xsl:attribute>
    <xsl:choose>
      <xsl:when test="not(preceding::chapter
                          or preceding::preface
                          or preceding::appendix
                          or preceding::article
                          or preceding::dedication
                          or parent::part
                          or parent::reference)">
        <!-- if there is a preceding component or we're in a part, the -->
        <!-- page numbering will already be adjusted -->
        <xsl:attribute name="initial-page-number">1</xsl:attribute>
      </xsl:when>
      <xsl:when test="$double.sided != 0">
        <xsl:attribute name="initial-page-number">auto-odd</xsl:attribute>
      </xsl:when>
    </xsl:choose>

    <xsl:apply-templates select="." mode="running.head.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <xsl:apply-templates select="." mode="running.foot.mode">
      <xsl:with-param name="master-reference" select="$master-reference"/>
    </xsl:apply-templates>

    <fo:flow flow-name="xsl-region-body">
      <xsl:call-template name="article.titlepage"/>

      <xsl:variable name="toc.params">
        <xsl:call-template name="find.path.params">
          <xsl:with-param name="table" select="normalize-space($generate.toc)"/>
        </xsl:call-template>
      </xsl:variable>

      <xsl:if test="contains($toc.params, 'toc')">
        <xsl:call-template name="component.toc"/>
        <xsl:call-template name="component.toc.separator"/>
      </xsl:if>
      <xsl:apply-templates/>
    </fo:flow>
  </fo:page-sequence>
</xsl:template>

<xsl:template match="article/artheader"></xsl:template>
<xsl:template match="article/articleinfo"></xsl:template>
<xsl:template match="article/title"></xsl:template>
<xsl:template match="article/subtitle"></xsl:template>

<xsl:template match="article/appendix">
  <xsl:variable name="id">
    <xsl:call-template name="object.id"/>
  </xsl:variable>

  <fo:block id='{$id}'>
    <xsl:call-template name="section.heading">
      <xsl:with-param name="level" select="2"/>
      <xsl:with-param name="title">
        <xsl:apply-templates select="." mode="object.title.markup"/>
      </xsl:with-param>
      <xsl:with-param name="titleabbrev">
        <xsl:apply-templates select="." mode="titleabbrev.markup"/>
      </xsl:with-param>
    </xsl:call-template>

    <xsl:apply-templates/>
  </fo:block>
</xsl:template>

<!-- ==================================================================== -->

</xsl:stylesheet>

