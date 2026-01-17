namespace Auth.Domain.Entities;
public class UserProfile
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public DateTime? DateOfBirth { get; set; }
    public string Department { get; set; }
    public int YearsOfService { get; set; }
    public string Position { get; set; }
    
    public virtual User User { get; set; }
}