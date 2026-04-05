import { NextResponse } from 'next/server';
import nodemailer from 'nodemailer';

export async function POST(req: Request) {
    try {
        const { name, email, message } = await req.json();

        // Verify environment variables
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
            console.error('Email credentials not configured');
            return NextResponse.json({ error: 'Server configuration error' }, { status: 500 });
        }

        const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 465,
            secure: true,
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        // Diagnostic: Verify connection configuration
        try {
            await transporter.verify();
            console.log('Transporter is ready to take our messages');
        } catch (verifyError) {
            console.error('Transporter verification failed:', verifyError);
            return NextResponse.json({ error: 'Mail server authentication failed' }, { status: 500 });
        }

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: 'xijingoing@gmail.com',
            replyTo: email,
            subject: `PhishGuard Contact: New message from ${name}`,
            text: `
Name: ${name}
Email (Sender): ${email}
Message:

${message}
      `,
            html: `
        <div style="font-family: sans-serif; padding: 20px; color: #333;">
          <h2 style="color: #00f0ff;">New Contact Request - PhishGuard</h2>
          <p><strong>Name:</strong> ${name}</p>
          <p><strong>Email:</strong> ${email}</p>
          <hr />
          <p><strong>Message:</strong></p>
          <p style="white-space: pre-wrap;">${message}</p>
        </div>
      `,
        };

        await transporter.sendMail(mailOptions);

        return NextResponse.json({ message: 'Email sent successfully' }, { status: 200 });
    } catch (error) {
        console.error('Nodemailer error:', error);
        return NextResponse.json({ error: 'Failed to send email' }, { status: 500 });
    }
}
