using API.FurnitureStore.API.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Options;
using MimeKit;
using MailKit;
using System.Linq.Expressions;
using System.Net.Mail;

namespace API.FurnitureStore.API.Services
{
    public class EmailService : IEmailSender
    {
        private readonly SmtpSettings _smptSettings;
        public EmailService(IOptions<SmtpSettings> smtpSettings)
        {
            _smptSettings = smtpSettings.Value;
        }
        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            try
            {
                var message = new MimeMessage();
                message.From.Add(new MailboxAddress(_smptSettings.SenderName, _smptSettings.SenderEmail));
                message.To.Add(new MailboxAddress("", email));
                message.Subject = subject;
                message.Body = new TextPart("html") { Text = htmlMessage};

                using (var client = new SmtpClient())
                {
                    await client.ConnectAsync(_smptSettings.Server);
                    await client.AuthenticateAsync(_smptSettings.UserName, _smptSettings.Password);
                    await client.SendAsync(message);
                    await client.DisconnectAsync(true);
                }
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}
