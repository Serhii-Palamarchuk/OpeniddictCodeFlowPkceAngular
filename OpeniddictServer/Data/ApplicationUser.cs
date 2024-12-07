using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace OpeniddictServer.Data;

public class ApplicationUser : IdentityUser<Guid>
{
    [PersonalData]
    public virtual string LastName { get; set; }

    [PersonalData]
    public virtual string FirstName { get; set; }

    [PersonalData]
    public virtual string? MiddleName { get; set; }

    [MaxLength(20)]
    [Column(TypeName = "varchar(20)")]
    public virtual string? InternalPhoneNumber { get; set; }
}
