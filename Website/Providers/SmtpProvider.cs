using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;

namespace Website.Providers
{
    public static class SmtpProvider
    {
        public static void SendMail(string from, string to, string subject, string body)
        {
            System.Net.Mail.MailMessage mail = new System.Net.Mail.MailMessage();
            mail.To.Add(to);
            mail.From = new MailAddress("waseemahmed.spirit@gmail.com", "", System.Text.Encoding.UTF8);
            mail.Subject = subject;
            mail.SubjectEncoding = System.Text.Encoding.UTF8;
            mail.Body = body;
            mail.BodyEncoding = System.Text.Encoding.UTF8;
            mail.IsBodyHtml = true;
            mail.Priority = MailPriority.High;
            SmtpClient client = new SmtpClient();
            client.Credentials = new System.Net.NetworkCredential("waseemahmed.spirit@gmail.com", "Panhyar12");
            //client.Port = 25;
            //client.Host = "relay-hosting.secureserver.net";
            client.Port = 587;
            client.Host = "smtp.gmail.com";
            try
            {
                client.Send(mail);
            }
            catch (Exception ex)
            {
                
            }

        }

        public static void SendEmail(string to, string subject, string body)
        {
            string HostAddress = ConfigurationManager.AppSettings["Host"].ToString();
            string FormEmailId = ConfigurationManager.AppSettings["MailFrom"].ToString();
            string Password = ConfigurationManager.AppSettings["Password"].ToString();
            string Port = ConfigurationManager.AppSettings["Port"].ToString();

            using (MailMessage mm = new MailMessage(FormEmailId, to))
            {
                try
                {
                    ServicePointManager.Expect100Continue = true;
                    ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
                    mm.Subject = subject;
                    mm.Body = body;
                    mm.IsBodyHtml = true;
                    SmtpClient smtp = new SmtpClient();
                    smtp.Host = HostAddress;
                    smtp.EnableSsl = true;
                    System.Net.NetworkCredential NetworkCred = new System.Net.NetworkCredential(FormEmailId, Password);
                    smtp.UseDefaultCredentials = true;
                    smtp.Credentials = NetworkCred;
                    smtp.Port = Convert.ToInt32(Port);
                    smtp.EnableSsl = true;
                    smtp.Send(mm);
                }
                catch (Exception ex)
                {
                    
                }
                
                //if (fuAttachment.HasFile)
                //{
                //    string FileName = Path.GetFileName(fuAttachment.PostedFile.FileName);
                //    mm.Attachments.Add(new Attachment(fuAttachment.PostedFile.InputStream, FileName));
                //}
                
            }
        }
    }
}