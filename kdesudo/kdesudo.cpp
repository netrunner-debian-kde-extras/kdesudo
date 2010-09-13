/***************************************************************************
                          kdesudo.cpp  -  the implementation of the 
                                          admin granting sudo widget
                             -------------------
    begin                : Sam Feb 15 15:42:12 CET 2003
    copyright            : (C) 2003 by Robert Gruber 
                                       <rgruber@users.sourceforge.net>
                           (C) 2007 by Martin Böhm <martin.bohm@kubuntu.org>
                                       Anthony Mercatante <tonio@kubuntu.org>
                                       Canonical Ltd (Jonathan Riddell 
                                                      <jriddell@ubuntu.com>)

 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <cstdio>
#include <cstdlib>
#include <csignal>

#include <sys/stat.h>
#include <sys/types.h>

#include <QFile>
#include <QDir>
#include <QDataStream>
#include <QString>
#include <QtCore/QStringList>
#include <QTemporaryFile>
#include <QProcess>

#include <KCmdLineArgs>
#include <KLocale>
#include <kmessagebox.h>
#include <KPushButton>
#include <KStandardDirs>
#include <KDebug>
#include <KPasswordDialog>
#include <KShell>
#include <KApplication>
#include <KWindowSystem>

#include "kdesudo.h"

KdeSudo::KdeSudo(const QString& icon, const QString& appname)
	: QObject(0)
{
	KCmdLineArgs *args = KCmdLineArgs::parsedArgs();

	/* pointer to the new process */
	p = NULL;

	/* error signal */
	bError = false;

	/* KCookie; used for display authentification */
	m_pCookie = new KDESu::KDESuPrivate::KCookie();

	//bool newDcop = args->isSet("newdcop");
	bool realtime = args->isSet("r");
	bool priority = args->isSet("p");
	bool showCommand = (!args->isSet("d"));
	bool changeUID = true;
	bool noExec = false;
	keepPwd = (!args->isSet("n"));
	emptyPwd = args->isSet("s");
	QString runas = args->getOption("u");
	QString cmd;
	int winid = -1;                           
	bool attach = args->isSet("attach");

	m_dialog = new KPasswordDialog(0);
	m_dialog->setDefaultButton( KDialog::Ok );

	if (attach)                              
	{                                         
		winid = args->getOption("attach").toInt(&attach, 0);
		KWindowSystem::setMainWindow(m_dialog, (WId)winid);
	}

	if (!args->isSet("c") && !args->count() && (!args->isSet("s")))
	{
		KMessageBox::information(0, i18n("No command arguments supplied!\n"
			"Usage: kdesudo [-u <runas>] <command>\n"
			"KdeSudo will now exit...")
		);
		noExec = true;
	}

	p = new KProcess;
	p->clearProgram();

	/* load the icon */
	m_dialog->setPixmap(icon);

	// Parsins args

	/* Get the comment out of cli args */
	QByteArray commentBytes = args->getOption("comment").toUtf8();
	QTextCodec* tCodecConv = QTextCodec::codecForLocale();
	QString comment = tCodecConv->toUnicode(commentBytes, commentBytes.size());

	if (args->isSet("f"))
	{
		// If file is writeable, do not change uid
		QString file = args->getOption("f");
		if (!file.isEmpty())
		{
			if (file.at(0) != '/')
			{
				KStandardDirs dirs;
				file = dirs.findResource("config", file);
				if (file.isEmpty())
				{
					kFatal(1206) << "Config file not found: " << file << "\n";
					exit(1);
				}
			}
			QFileInfo fi(file);
			if (!fi.exists())
			{
				kFatal(1206) << "File does not exist: " << file << "\n";
				exit(1);
			}
			if (fi.isWritable())
			{
				changeUID = false;
			}
		}
	}

	connect( p, SIGNAL(readyReadStandardOutput()), this,
		SLOT(parseOutput()) );

	connect( p, SIGNAL(readyReadStandardError()), this, 
		SLOT(parseOutput()) );

	connect( p, SIGNAL(finished(int)), this, 
		SLOT(procExited(int)));

	connect( m_dialog, SIGNAL( gotPassword( const QString& , bool ) ), 
		this, SLOT( pushPassword( const QString &) ) );

        connect( m_dialog, SIGNAL( rejected() ), this,
                SLOT(slotCancel()));

	// Generate the xauth cookie and put it in a tempfile
	// set the environment variables to reflect that.
	// Default cookie-timeout is 60 sec. .
	// 'man xauth' for more info on xauth cookies.

	QTemporaryFile* tmpFile=new QTemporaryFile("/tmp/kdesudo-XXXXXX-xauth");
	tmpFile->open();
	QString m_tmpName=tmpFile->fileName();
	delete tmpFile;

	QByteArray disp = m_pCookie->display();

	// Create two processes, one for each xauth call
	QProcess xauth_ext;
	QProcess xauth_merge;

	// This makes "xauth extract - $DISPLAY | xauth -f /tmp/kdesudo-... merge -"
	xauth_ext.setStandardOutputProcess( &xauth_merge );

	// Start the first
	xauth_ext.start("xauth", QStringList() << "extract" << "-" << QString::fromLocal8Bit(disp), QIODevice::ReadOnly );
	if (!xauth_ext.waitForStarted())
                return;

	// Start the second
	xauth_merge.start("xauth", QStringList() << "-f" << m_tmpName << "merge" << "-", QIODevice::WriteOnly );
	if (!xauth_merge.waitForStarted())
                return;

	// If they ended, close it all
	if (!xauth_merge.waitForFinished())
                return;
	xauth_merge.close();

	if (!xauth_ext.waitForFinished())
                return;
	xauth_ext.close();

	// non root users need to be able to read the xauth file.
	// the xauth file is deleted when kdesudo exits. security?
	QFile tf;
	tf.setFileName(m_tmpName);

	if (!runas.isEmpty() && runas != "root" && tf.exists())
		chmod(QFile::encodeName(m_tmpName),0644);

	p->setEnv("DISPLAY", disp);
	p->setEnv("XAUTHORITY", m_tmpName);

	if (emptyPwd)
		*p << "sudo" << "-k";
	else
	{
		if (changeUID)
		{
			*p << "sudo" << "-H" << "-S" << "-p" << "passprompt";

			if (!runas.isEmpty())
				*p << "-u" << runas;
			*p << "--";
		}

		if (realtime)
		{
			*p << "nice" << "-n" << "10";
			m_dialog->addCommentLine(i18n("Priority:"), i18n("realtime:") + 
				QChar(' ') + QString("50/100"));
			*p << "--";
		}
		else if (priority)
		{
			QString n = args->getOption("p");
			int intn = atoi(n.toUtf8());
			intn =  (intn * 40 / 100) - (20 + 0.5);
		
			QString strn;
			strn.sprintf("%d",intn);

			*p << "nice" << "-n" << strn;
			m_dialog->addCommentLine(i18n("Priority:"), n + QString("/100"));
			*p << "--";
		}



		if (args->isSet("c"))
		{
			QString command = args->getOption("c");
			cmd += command;
			*p << "sh";
			*p << "-c";
			*p << command;
		}

		else if (args->count())
		{
			for (int i = 0; i < args->count(); i++)
			{
				if ((!args->isSet("c")) && (i == 0))
				{
					QStringList argsSplit = KShell::splitArgs(args->arg(i));
					for (int j = 0; j < argsSplit.count(); j++)
					{
						*p << validArg(argsSplit[j]);
						if (j == 0)
							cmd += validArg(argsSplit[j]) + QChar(' ');
						else
							cmd += KShell::quoteArg(validArg(argsSplit[j])) + QChar(' ');
					}
				}
				else
				{
					*p << validArg(args->arg(i));
					cmd += validArg(args->arg(i)) + QChar(' ');
				}
			}
		}
		// strcmd needs to be defined
		if (showCommand && !cmd.isEmpty())
			m_dialog->addCommentLine(i18n("Command:"), cmd);
	}

	if (comment.isEmpty())
	{
		QString defaultComment = "<b>%1</b> " + i18n("needs administrative privileges. ");

		if (runas.isEmpty() || runas == "root")
			defaultComment += i18n("Please enter your password.");
		else
			defaultComment += i18n("Please enter password for <b>%1</b>.", runas);

		if (!appname.isEmpty())
			m_dialog->setPrompt(defaultComment.arg(appname));
		else
			m_dialog->setPrompt(defaultComment.arg(cmd));
	}
	else
		m_dialog->setPrompt(comment);

	p->setOutputChannelMode( KProcess::MergedChannels );

	if (noExec) {
		exit(0);
	}
	else
		p->start();
}

KdeSudo::~KdeSudo()
{
	delete m_dialog;
}

void KdeSudo::error(const QString& msg) {
	bError = true;
	KMessageBox::error(0, msg);
	KApplication::kApplication()->exit(1);
}

void KdeSudo::parseOutput()
{
	QString strOut = p->readAllStandardOutput();

	static int badpass = 0;

	if (strOut.contains("try again"))
	{
		badpass++;
		if (badpass == 1)
		{
			m_dialog->addCommentLine(i18n("<b>Warning: </b>"), i18n("<b>Incorrect password, please try again.</b>"));
			m_dialog->show();
		}
		else if (badpass == 2)
			m_dialog->show();
		else
			error(i18n("Wrong password! Exiting..."));
		
	}
	else if (strOut.contains("command not found"))
        	error(i18n("Command not found!"));
	else if (strOut.contains("is not in the sudoers file"))
		error(i18n("Your username is unknown to sudo!"));
	else if (strOut.contains("is not allowed to execute"))
		error(i18n("Your user is not allowed to run the specified command!"));
	else if (strOut.contains("is not allowed to run sudo on"))
		error(i18n("Your user is not allowed to run sudo on this host!"));
	else if (strOut.contains("may not run sudo on"))
		error(i18n("Your user is not allowed to run sudo on this host!"));
	else if ((strOut.contains("passprompt")) || (strOut.contains("PIN (CHV2)")))
	{
		m_dialog->setPassword(QString());
		m_dialog->show();
	}
	else
		fprintf(stdout, "%s", strOut.toLatin1().constData());
}

void KdeSudo::procExited(int exitCode)
{
	if (!keepPwd && unCleaned)
	{
		unCleaned = false;
		p->clearProgram(); //clearArguments()
		*p << "sudo" << "-k";
		p->start(); 
	}

	if (!bError)
	{
		if (!m_tmpName.isEmpty())
			QFile::remove(m_tmpName);
	}
	KApplication::kApplication()->exit(exitCode);
}

void KdeSudo::pushPassword(const QString& pwd)
{
	p->write(pwd.toLatin1()+"\n");
}

void KdeSudo::slotCancel()
{
	KApplication::kApplication()->exit(1);
}

void KdeSudo::slotUser1()
{
	m_dialog->done(AsUser);
}

void KdeSudo::blockSigChild()
{
	sigset_t sset;
	sigemptyset(&sset);
	sigaddset(&sset, SIGCHLD);
	sigprocmask(SIG_BLOCK, &sset, 0L);
}

void KdeSudo::unblockSigChild()
{
	sigset_t sset;
	sigemptyset(&sset);
	sigaddset(&sset, SIGCHLD);
	sigprocmask(SIG_UNBLOCK, &sset, 0L);
}


QString KdeSudo::validArg(QString arg)
{
	QChar firstChar = arg.at(0);
	QChar lastChar = arg.at(arg.length() - 1);

	if ( (firstChar == '"' && lastChar == '"') || (firstChar == '\'' && lastChar == '\'') )
	{
		arg = arg.remove(0, 1);
		arg = arg.remove(arg.length() - 1, 1);
	}
	return arg;
}
